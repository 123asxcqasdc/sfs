/**
 * SFS (Simple File System) — Kotlin/Android Parser
 * Tree-based filesystem storing filenames + file content.
 * All 256 byte values allowed in names and content.
 *
 * HEADER v2 (144 bytes):
 *   [0-3]    magic: "SFSY"
 *   [4-5]    version: uint16 LE (2)
 *   [6-7]    root_count: uint16 LE
 *   [8-39]   sha256: 32 bytes — hash of ALL bytes from offset 144 to EOF
 *   [40-71]  publisher public key: 32 bytes Ed25519 (zeros if unsigned)
 *   [72-79]  signer_id: 8 bytes = first 8 bytes of SHA-256(pubkey)
 *   [80-143] signature: 64 bytes Ed25519 (zeros if unsigned)
 *            signed message = bytes[0..79] ++ bytes[144..EOF]
 *   [144..]  tree data (content)
 *
 * HEADER v1 (legacy, 40 bytes, hash-only):
 *   [0-3]    magic: "SFSY"
 *   [4-5]    version: uint16 LE (1)
 *   [6-7]    root_count: uint16 LE
 *   [8-39]   sha256: 32 bytes — hash of bytes from offset 40 to EOF
 *   [40..]   tree data
 *
 * NODE (recursive):
 *   [0]     type: 0x01 = file, 0x02 = directory
 *   [1-2]   name_len: uint16 LE
 *   [3..N]  name: raw bytes (any 0x00-0xFF)
 *   if directory:
 *     [2 bytes] child_count: uint16 LE
 *     followed by child_count NODEs
 *   if file (type 0x01):
 *     [4 bytes] content_len: uint32 LE
 *     [content_len bytes] content
 *
 * Note: Ed25519 support requires Android API 33+ (java.security.Signature "Ed25519").
 * For older devices, add org.bouncycastle:bcprov-android or spongycastle as a dependency
 * and register it as a provider before calling sign/verify.
 */

import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class FsNode(
    val type: Int,
    val name: ByteArray,
    val content: ByteArray? = null,
    val children: MutableList<FsNode> = mutableListOf()
) {
    companion object {
        const val TYPE_FILE = 0x01
        const val TYPE_DIR = 0x02
        const val HEADER_V1_SIZE = 40
        const val HEADER_V2_SIZE = 144
        val MAGIC = byteArrayOf(0x53, 0x46, 0x53, 0x59) // "SFSY"
    }

    val isDir: Boolean get() = type == TYPE_DIR

    var parent: FsNode? = null
        internal set

    /** Decode as ISO-8859-1 (latin1) to preserve all 256 byte values. */
    fun nameString(): String = String(name, Charsets.ISO_8859_1)

    fun find(name: String): FsNode? = children.firstOrNull { it.nameString() == name }

    fun path(): String {
        val parts = mutableListOf<String>()
        var node: FsNode? = this
        while (node != null) {
            parts.add(0, node.nameString())
            node = node.parent
        }
        return parts.joinToString("/")
    }

    fun dump(indent: String = "", sb: StringBuilder = StringBuilder()): String {
        val label = if (isDir) "${nameString()}/" else "${nameString()} (${content?.size ?: 0} B)"
        sb.append(indent).append(label).append('\n')
        for (child in children) child.dump("$indent  ", sb)
        return sb.toString()
    }
}

class FsParser {
    data class Root(
        val version: Int,
        val roots: List<FsNode>,
        val hash: ByteArray,
        val hashValid: Boolean,
        val signerId: ByteArray?,
        val pubkey: ByteArray?,
        val signatureValid: Boolean
    )

    data class VerifyResult(
        val signatureValid: Boolean,
        val signerId: ByteArray?,
        val pubkey: ByteArray?,
        val trusted: Boolean
    )

    class ParseException(message: String) : Exception(message)

    companion object {
        private const val OID_ED25519 = "1.3.101.112"

        fun sha256(data: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(data)

        // ---- Low-level Ed25519 via java.security (API 33+ / BouncyCastle) ----

        private fun edPrivateKey(seed: ByteArray): java.security.PrivateKey {
            // PKCS8 DER: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING (32-byte seed) }
            val pkcs8 = byteArrayOf(
                0x30, 0x2e, 0x02, 0x01, 0x00,
                0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
                0x22, 0x04, 0x20
            ) + seed
            return KeyFactory.getInstance("Ed25519")
                .generatePrivate(PKCS8EncodedKeySpec(pkcs8))
        }

        private fun edPublicKey(pub32: ByteArray): java.security.PublicKey {
            // SPKI DER: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (33 bytes, 0 unused) }
            val spki = byteArrayOf(
                0x30, 0x2a,
                0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
                0x03, 0x21, 0x00
            ) + pub32
            return KeyFactory.getInstance("Ed25519")
                .generatePublic(X509EncodedKeySpec(spki))
        }

        fun signBytes(data: ByteArray, seed: ByteArray): ByteArray {
            val sig = Signature.getInstance("Ed25519")
            sig.initSign(edPrivateKey(seed))
            sig.update(data)
            return sig.sign() // 64 bytes
        }

        fun verifyBytes(data: ByteArray, signature: ByteArray, pub32: ByteArray): Boolean {
            return try {
                val sig = Signature.getInstance("Ed25519")
                sig.initVerify(edPublicKey(pub32))
                sig.update(data)
                sig.verify(signature)
            } catch (e: Exception) {
                false // Ed25519 not supported or key mismatch
            }
        }

        fun publicKeyFromSeed(seed: ByteArray): ByteArray {
            val kf = KeyFactory.getInstance("Ed25519")
            val priv = edPrivateKey(seed)
            // Derive public from private by signing then verifying? No — use KeyPair gen
            // android KeyPairGenerator doesn't expose raw seed input easily.
            // Instead, use BouncyCastle or: encode seed as PKCS8, derive via sign+verify? Not available.
            // Most reliable on API 33+: keypair generation from seed not directly exposed.
            // Fallback: import via BouncyCastle (Ed25519PublicKeyParameters).
            // Without BouncyCastle: require the caller to provide the public key externally.
            throw UnsupportedOperationException(
                "Deriving Ed25519 public key from seed requires BouncyCastle on Android. " +
                "Pass the public key directly or add org.bouncycastle:bcprov-android."
            )
        }

        /** Verify the SHA-256 hash embedded in the header. */
        fun verifyHash(data: ByteArray): Boolean = try {
            parse(data).hashValid
        } catch (e: Exception) {
            false
        }

        /** Verify signature against an allowlist of trusted publisher public keys. */
        fun verifySignature(data: ByteArray, trustedPubkeys: List<ByteArray> = emptyList()): VerifyResult {
            return try {
                val r = parse(data)
                val isTrusted = r.pubkey != null && r.pubkey.any { it != 0.toByte() } &&
                        trustedPubkeys.any { pk ->
                            pk.size == r.pubkey.size && pk.contentEquals(r.pubkey)
                        }
                VerifyResult(r.signatureValid, r.signerId, r.pubkey, isTrusted)
            } catch (e: Exception) {
                VerifyResult(false, null, null, false)
            }
        }

        fun parse(data: ByteArray): Root {
            if (data.size < FsNode.HEADER_V1_SIZE) throw ParseException("Buffer too small for SFS header")

            // Magic
            for (i in 0 until 4) {
                if (data[i] != FsNode.MAGIC[i]) throw ParseException("Invalid magic")
            }

            val version = uint16(data, 4)
            val rootCount = uint16(data, 6)

            val contentOffset: Int
            var pubkey: ByteArray? = null
            var signerId: ByteArray? = null
            var signature: ByteArray? = null

            if (version >= 2 && data.size >= FsNode.HEADER_V2_SIZE) {
                contentOffset = FsNode.HEADER_V2_SIZE
                pubkey = data.copyOfRange(40, 72)
                signerId = data.copyOfRange(72, 80)
                signature = data.copyOfRange(80, 144)
            } else {
                contentOffset = FsNode.HEADER_V1_SIZE
            }

            // Hash check
            val storedHash = data.copyOfRange(8, 40)
            val computedHash = sha256(data.copyOfRange(contentOffset, data.size))
            val hashValid = storedHash.contentEquals(computedHash)

            // Signature verification (v2 only, skip if pubkey all zeros)
            var signatureValid = false
            if (version >= 2 && pubkey != null && signature != null) {
                val hasKey = pubkey.any { it != 0.toByte() }
                if (hasKey) {
                    val signedMsg = ByteArray(80 + (data.size - contentOffset))
                    data.copyInto(signedMsg, 0, 0, 80)
                    data.copyInto(signedMsg, 80, contentOffset, data.size)
                    signatureValid = verifyBytes(signedMsg, signature, pubkey)
                }
            }

            val roots = mutableListOf<FsNode>()
            var offset = contentOffset
            repeat(rootCount) {
                val parsed = parseNode(data, offset)
                offset = parsed.offset
                roots.add(parsed.node)
            }

            setParents(roots, null)
            return Root(version, roots, computedHash, hashValid, signerId, pubkey, signatureValid)
        }

        private fun parseNode(data: ByteArray, start: Int): ParsedNode {
            var offset = start
            if (offset >= data.size) throw ParseException("Unexpected end of data")

            val type = data[offset].toInt() and 0xFF
            offset++
            if (type != FsNode.TYPE_FILE && type != FsNode.TYPE_DIR) {
                throw ParseException("Unknown node type: 0x%02X".format(type))
            }

            val nameLen = uint16(data, offset)
            offset += 2
            if (offset + nameLen > data.size) throw ParseException("Truncated name")
            val name = data.copyOfRange(offset, offset + nameLen)
            offset += nameLen

            val node: FsNode
            if (type == FsNode.TYPE_DIR) {
                val childCount = uint16(data, offset)
                offset += 2
                val children = mutableListOf<FsNode>()
                repeat(childCount) {
                    val child = parseNode(data, offset)
                    offset = child.offset
                    children.add(child.node)
                }
                node = FsNode(type, name, null, children)
            } else {
                if (offset + 4 > data.size) throw ParseException("Truncated content length")
                val contentLen = (data[offset].toInt() and 0xFF) or
                        ((data[offset + 1].toInt() and 0xFF) shl 8) or
                        ((data[offset + 2].toInt() and 0xFF) shl 16) or
                        ((data[offset + 3].toInt() and 0xFF) shl 24)
                offset += 4
                if (offset + contentLen > data.size) throw ParseException("Truncated content")
                val content = data.copyOfRange(offset, offset + contentLen)
                offset += contentLen
                node = FsNode(type, name, content, mutableListOf())
            }

            return ParsedNode(node, offset)
        }

        private fun uint16(data: ByteArray, offset: Int): Int =
            (data[offset].toInt() and 0xFF) or ((data[offset + 1].toInt() and 0xFF) shl 8)

        private fun setParents(nodes: List<FsNode>, parent: FsNode?) {
            for (node in nodes) {
                node.parent = parent
                if (node.isDir) setParents(node.children, node)
            }
        }

        private class ParsedNode(val node: FsNode, val offset: Int)

        /**
         * Serialize roots into an SFS v2 container with optional Ed25519 signature.
         * @param seed publisher private seed (32 bytes). Null → unsigned (hash only).
         * @param pubKey publisher public key (32 bytes). Required alongside seed.
         */
        fun serialize(roots: List<FsNode>, seed: ByteArray? = null, pubKey: ByteArray? = null): ByteArray {
            // Build tree data
            val tree = DataWriter()
            for (root in roots) serializeNode(root, tree)
            val treeBytes = tree.toByteArray()
            val hash = sha256(treeBytes)

            // Header
            val header = DataWriter()
            header.writeBytes(FsNode.MAGIC)
            header.writeShort(2) // version 2
            header.writeShort(roots.size)
            header.writeBytes(hash)

            // Sign
            if (seed != null && pubKey != null) {
                header.writeBytes(pubKey)
                val sid = sha256(pubKey)
                header.writeBytes(sid.copyOf(8))
                // Compute signed message = header[0..79] ++ treeBytes
                val headerBytes = header.toByteArray()
                val msg = ByteArray(80 + treeBytes.size)
                System.arraycopy(headerBytes, 0, msg, 0, 80)
                System.arraycopy(treeBytes, 0, msg, 80, treeBytes.size)
                val sig = signBytes(msg, seed)
                header.writeBytes(sig)
            } else {
                header.writeBytes(ByteArray(32)) // empty pubkey
                header.writeBytes(ByteArray(8))  // empty signer_id
                header.writeBytes(ByteArray(64)) // empty signature
            }

            val headerBytes = header.toByteArray()
            // Assemble final: header (144 B) + tree
            val out = ByteArray(FsNode.HEADER_V2_SIZE + treeBytes.size)
            System.arraycopy(headerBytes, 0, out, 0, headerBytes.size.coerceAtMost(FsNode.HEADER_V2_SIZE))
            System.arraycopy(treeBytes, 0, out, FsNode.HEADER_V2_SIZE, treeBytes.size)
            return out
        }

        private fun serializeNode(node: FsNode, out: DataWriter) {
            out.writeByte(node.type)
            out.writeShort(node.name.size)
            out.writeBytes(node.name)
            if (node.isDir) {
                out.writeShort(node.children.size)
                for (child in node.children) serializeNode(child, out)
            } else {
                val content = node.content ?: ByteArray(0)
                out.writeUInt(content.size)
                out.writeBytes(content)
            }
        }

        private class DataWriter {
            private val buf = ByteArrayOutputStream()

            fun writeByte(b: Int) = buf.write(b and 0xFF)
            fun writeShort(v: Int) {
                buf.write(v and 0xFF)
                buf.write((v shr 8) and 0xFF)
            }
            fun writeUInt(v: Int) {
                buf.write(v and 0xFF)
                buf.write((v shr 8) and 0xFF)
                buf.write((v shr 16) and 0xFF)
                buf.write((v ushr 24) and 0xFF)
            }
            fun writeBytes(bytes: ByteArray) = buf.write(bytes, 0, bytes.size)
            fun toByteArray(): ByteArray = buf.toByteArray()
        }
    }
}