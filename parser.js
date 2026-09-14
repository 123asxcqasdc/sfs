/**
 * SFS (Simple File System) — JS Parser
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
 */

const MAGIC = new Uint8Array([0x53, 0x46, 0x53, 0x59]); // "SFSY"
const TYPE_FILE = 0x01;
const TYPE_DIR = 0x02;
const HEADER_V1_SIZE = 40;
const HEADER_V2_SIZE = 144;

// ---- Pure JS SHA-256 (sync, works in Node + browser) ----
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

const H_INIT = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);

function rotr(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

/**
 * @param {Uint8Array} data
 * @returns {Uint8Array} 32-byte SHA-256
 */
function sha256(data) {
  const w = new Uint32Array(64);
  const h = new Uint32Array(H_INIT);

  const l = data.length;
  const bitLenHi = Math.floor(l / 0x20000000);
  const bitLenLo = (l << 3) >>> 0;

  const paddedLen = (((l + 8) >> 6) + 1) << 6;
  const msg = new Uint8Array(paddedLen);
  msg.set(data);
  msg[l] = 0x80;
  const dv = new DataView(msg.buffer);
  dv.setUint32(paddedLen - 8, bitLenHi, false);
  dv.setUint32(paddedLen - 4, bitLenLo, false);

  for (let i = 0; i < paddedLen; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4, false);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }

    let a = h[0], b = h[1], c = h[2], d = h[3];
    let e = h[4], f = h[5], g = h[6], hh = h[7];

    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (hh + S1 + ch + K[t] + w[t]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }

    h[0] = (h[0] + a) >>> 0;
    h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0;
    h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0;
    h[7] = (h[7] + hh) >>> 0;
  }

  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, h[i], false);
  return out;
}

class FsNode {
  /**
   * @param {number} type TYPE_FILE or TYPE_DIR
   * @param {Uint8Array} name raw name bytes
   * @param {Uint8Array|null} content file content (files only)
   * @param {FsNode[]} children children (directories only)
   */
  constructor(type, name, content = null, children = []) {
    this.type = type;
    this.name = name;
    this.content = content;
    this.children = children;
  }

  isDir() {
    return this.type === TYPE_DIR;
  }

  /** Decode as latin1 to preserve all 256 byte values. */
  nameString() {
    let s = "";
    for (let i = 0; i < this.name.length; i++) s += String.fromCharCode(this.name[i]);
    return s;
  }

  toString(indent = "") {
    const label = this.isDir() ? this.nameString() + "/" : this.nameString() + ` (${this.content?.length ?? 0} B)`;
    let out = indent + label + "\n";
    for (const child of this.children) out += child.toString(indent + "  ");
    return out;
  }

  find(name) {
    for (const child of this.children) if (child.nameString() === name) return child;
    return null;
  }

  path() {
    return this._pathParts().join("/");
  }

  _pathParts() {
    if (!this._parent) return [this.nameString()];
    return [...this._parent._pathParts(), this.nameString()];
  }
}

class FsParser {
  /**
   * Parse an SFS container.
   * @param {ArrayBuffer|Uint8Array} buffer
   * @returns {{ version: number, roots: FsNode[], hash: Uint8Array, hashValid: boolean,
   *             signerId: Uint8Array|null, pubkey: Uint8Array|null,
   *             signatureValid: boolean }}
   */
  static parse(buffer) {
    const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const data = view;

    if (data.length < HEADER_V1_SIZE) throw new Error("Buffer too small for SFS header");

    // Magic
    for (let i = 0; i < 4; i++) {
      if (data[i] !== MAGIC[i]) {
        throw new Error(`Invalid magic: expected SFSY, got ${String.fromCharCode(...data.slice(0, 4))}`);
      }
    }

    // Version
    const version = data[4] | (data[5] << 8);
    const rootCount = data[6] | (data[7] << 8);

    let contentOffset;
    let pubkey = null, signerId = null, signature = null;
    if (version >= 2 && data.length >= HEADER_V2_SIZE) {
      contentOffset = HEADER_V2_SIZE;
      pubkey = data.slice(40, 72);
      signerId = data.slice(72, 80);
      signature = data.slice(80, 144);
    } else {
      contentOffset = HEADER_V1_SIZE;
    }

    // Hash verification
    const storedHash = data.slice(8, 8 + 32);
    const computedHash = sha256(data.subarray(contentOffset));
    let hashValid = true;
    for (let i = 0; i < 32; i++) {
      if (storedHash[i] !== computedHash[i]) { hashValid = false; break; }
    }

    // Signature verification (v2 only, skip if all zeros)
    let signatureValid = false;
    if (version >= 2 && pubkey && signature) {
      let hasNonZero = false;
      for (let i = 0; i < 32; i++) if (pubkey[i] !== 0) { hasNonZero = true; break; }
      if (hasNonZero) {
        // Reconstruct signed message: header[0..79] ++ content
        const msgLen = 80 + (data.length - contentOffset);
        const msg = new Uint8Array(msgLen);
        msg.set(data.subarray(0, 80));                 // header without signature
        msg.set(data.subarray(contentOffset), 80);     // content
        signatureValid = _ed25519_verify(msg, signature, pubkey);
      }
    }

    // Parse tree
    let offset = contentOffset;
    const roots = [];
    for (let i = 0; i < rootCount; i++) {
      const { node, newOffset } = FsParser._parseNode(data, offset);
      roots.push(node);
      offset = newOffset;
    }

    FsParser._setParents(roots, null);
    return { version, roots, hash: computedHash, hashValid, signerId, pubkey, signatureValid };
  }

  static _parseNode(data, offset) {
    const type = data[offset++];
    if (type !== TYPE_FILE && type !== TYPE_DIR) {
      throw new Error(`Unknown node type: 0x${type.toString(16)}`);
    }

    const nameLen = data[offset] | (data[offset + 1] << 8);
    offset += 2;
    const name = data.slice(offset, offset + nameLen);
    offset += nameLen;

    let content = null;
    const children = [];

    if (type === TYPE_DIR) {
      const childCount = data[offset] | (data[offset + 1] << 8);
      offset += 2;
      for (let i = 0; i < childCount; i++) {
        const { node, newOffset } = FsParser._parseNode(data, offset);
        children.push(node);
        offset = newOffset;
      }
    } else {
      const contentLen = data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
      offset += 4;
      if (contentLen > data.length - offset) throw new Error("Truncated file content");
      content = data.slice(offset, offset + contentLen);
      offset += contentLen;
    }

    return { node: new FsNode(type, name, content, children), newOffset: offset };
  }

  static _setParents(nodes, parent) {
    for (const node of nodes) {
      node._parent = parent;
      if (node.isDir()) FsParser._setParents(node.children, node);
    }
  }

  /** @returns {boolean} */
  static verifyHash(buffer) {
    try { return FsParser.parse(buffer).hashValid; } catch { return false; }
  }

  /** @returns {{ signatureValid: boolean, signerId: Uint8Array|null, pubkey: Uint8Array|null }} */
  static verifySignature(buffer, trustedPubkeys = []) {
    try {
      const r = FsParser.parse(buffer);
      let trusted = false;
      if (r.pubkey && trustedPubkeys.length) {
        for (const pk of trustedPubkeys) {
          if (r.pubkey.length === pk.length && r.pubkey.every((v, i) => v === pk[i])) { trusted = true; break; }
        }
      }
      return { signatureValid: r.signatureValid, signerId: r.signerId, pubkey: r.pubkey, trusted };
    } catch {
      return { signatureValid: false, signerId: null, pubkey: null, trusted: false };
    }
  }

  /**
   * Serialize roots into an SFS v2 container with Ed25519 signature.
   * @param {FsNode[]} roots
   * @param {{ seed?: Uint8Array }} opts  – if seed provided, sign with it
   * @returns {Uint8Array}
   */
  static serialize(roots, opts = {}) {
    const { seed } = opts;
    const chunks = [];

    // Header placeholder (144 bytes for v2)
    const header = new Uint8Array(HEADER_V2_SIZE);
    header[0] = 0x53; header[1] = 0x46; header[2] = 0x53; header[3] = 0x59;
    header[4] = 2; // version 2
    header[6] = roots.length & 0xff;
    header[7] = (roots.length >> 8) & 0xff;
    chunks.push(header);

    // Tree data
    for (const root of roots) FsParser._serializeNode(root, chunks);

    // Merge
    let totalLen = 0;
    for (const c of chunks) totalLen += c.length;
    const result = new Uint8Array(totalLen);
    let pos = 0;
    for (const c of chunks) { result.set(c, pos); pos += c.length; }

    // Hash over content (offset 144..EOF)
    const hash = sha256(result.subarray(HEADER_V2_SIZE));
    result.set(hash, 8);

    // Sign if seed provided
    if (seed) {
      const pub = _ed25519_pubkey(seed);
      result.set(pub, 40);
      const sid = sha256(pub);
      result.set(sid.subarray(0, 8), 72);

      // Signed message = header[0..79] ++ content
      const signedMsg = new Uint8Array(80 + (result.length - HEADER_V2_SIZE));
      signedMsg.set(result.subarray(0, 80));
      signedMsg.set(result.subarray(HEADER_V2_SIZE), 80);
      const sig = _ed25519_sign(signedMsg, seed);
      result.set(sig, 80);
    }

    return result;
  }

  static _serializeNode(node, chunks) {
    chunks.push(new Uint8Array([node.type]));

    const nameLenBuf = new Uint8Array(2);
    nameLenBuf[0] = node.name.length & 0xff;
    nameLenBuf[1] = (node.name.length >> 8) & 0xff;
    chunks.push(nameLenBuf);
    chunks.push(node.name);

    if (node.isDir()) {
      const childCountBuf = new Uint8Array(2);
      childCountBuf[0] = node.children.length & 0xff;
      childCountBuf[1] = (node.children.length >> 8) & 0xff;
      chunks.push(childCountBuf);
      for (const child of node.children) FsParser._serializeNode(child, chunks);
    } else {
      const content = node.content || new Uint8Array(0);
      const lenBuf = new Uint8Array(4);
      lenBuf[0] = content.length & 0xff;
      lenBuf[1] = (content.length >> 8) & 0xff;
      lenBuf[2] = (content.length >> 16) & 0xff;
      lenBuf[3] = (content.length >>> 24) & 0xff;
      chunks.push(lenBuf);
      chunks.push(content);
    }
  }
}

// ---- Ed25519 glue (works in Node + browser via ed25519.js or global) ----
function _loadEd25519() {
  if (typeof require === "function") {
    // Node
    const m = require("./ed25519.js");
    return { pubkey: m.publicKeyFromSeed_ed25519, sign: m.sign, verify: m.verify };
  }
  if (typeof window !== "undefined" && window.Ed25519) return window.Ed25519;
  throw new Error("Ed25519 module not found. Load ed25519.js before parser.js in browser.");
}
let _ed = null;
function ed() { if (!_ed) _ed = _loadEd25519(); return _ed; }
function _ed25519_pubkey(seed) { return new Uint8Array(ed().pubkey(seed)); }
function _ed25519_sign(msg, seed) { const r = ed().sign(msg, seed); return r.signature; }
function _ed25519_verify(msg, sig, pub) { return ed().verify(msg, sig, pub); }

// Node.js export
if (typeof module !== "undefined") {
  module.exports = { FsParser, FsNode, sha256, TYPE_FILE, TYPE_DIR };
}

// Browser/global
if (typeof window !== "undefined") {
  window.FsParser = FsParser;
  window.FsNode = FsNode;
  window.sha256 = sha256;
  window.TYPE_FILE = TYPE_FILE;
  window.TYPE_DIR = TYPE_DIR;
}