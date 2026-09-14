#!/usr/bin/env node
/**
 * Demo writer: builds an SFS v2 tree signed by a publisher (Ed25519).
 * - filenames/content use ALL 256 byte values
 * - SHA-256 integrity hash in header
 * - Ed25519 signature by the publisher over header + whole tree
 */

const fs = require("fs");
const crypto = require("crypto");
const { FsParser, FsNode, TYPE_FILE, TYPE_DIR } = require("./parser.js");
const { generateKeyPair } = require("./ed25519.js");

function strToBytes(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

function file(name, content) {
  return new FsNode(TYPE_FILE, strToBytes(name), strToBytes(content));
}

function dir(name, children = []) {
  return new FsNode(TYPE_DIR, strToBytes(name), null, children);
}

function buildTree() {
  const allSyms = dir(String.fromCharCode(...Array.from({ length: 256 }, (_, i) => i)));

  const mixedName = String.fromCharCode(0x00, 0x0A, 0x41, 0x7F, 0x80, 0xFF, 0x42);
  allSyms.children.push(dir(mixedName, [
    file("plain.txt", "hello world, this is the file content for SFS demo."),
    file(String.fromCharCode(0x00), "\x00\x01\x02 binary content"),
    file(String.fromCharCode(0xFF), String.fromCharCode(...Array.from({ length: 256 }, (_, i) => i))),
    file("all-bytes.bin", String.fromCharCode(...Array.from({ length: 256 }, (_, i) => i))),
  ]));

  allSyms.children.push(dir("apps", [
    dir("com.example.hello", [
      file("app.apk", crypto.randomBytes(512).toString("latin1")),
      file("signature.sig", "fake-dev-signature"),
    ]),
  ]));

  allSyms.children.push(dir("src", [
    file("Main.kt", "fun main() { println(\"SFS!\") }"),
    dir("res", [file("strings.xml", "<string name=\"sfs\">SFS</string>")]),
  ]));

  return [allSyms];
}

// === Publisher key pair ===
const args = process.argv.slice(2);
const unsignedMode = args.includes("--unsigned");
const outPath = args.find((a) => !a.startsWith("--")) || "tree.sfs";

let publisherSeed = null;
let store = null;
if (!unsignedMode) {
  const pubPath = "publisher.pub";
  const seedPath = "publisher.seed";
  if (fs.existsSync(seedPath)) {
    publisherSeed = new Uint8Array(fs.readFileSync(seedPath));
    store = new Uint8Array(fs.readFileSync(pubPath));
    console.log("Publisher: loaded existing key from", seedPath);
  } else {
    const kp = generateKeyPair();
    publisherSeed = kp.seed;
    store = kp.publicKey;
    fs.writeFileSync(seedPath, Buffer.from(kp.seed));
    fs.writeFileSync(pubPath, Buffer.from(kp.publicKey));
    console.log("Publisher: generated key, saved seed/pub");
  }
} else {
  console.log("Unsigned mode: packaging WITHOUT publisher signature (hash-only).");
}

const roots = buildTree();
const opts = unsignedMode ? {} : { seed: publisherSeed };
const bytes = FsParser.serialize(roots, opts);
fs.writeFileSync(outPath, Buffer.from(bytes));
console.log(`Wrote ${bytes.length} bytes to ${outPath} (v2, ${unsignedMode ? "UNSIGNED" : "signed by publisher"})`);

// === Verify ===
const parsed = FsParser.parse(bytes);
console.log("Hash valid:", parsed.hashValid);
console.log("Signature valid:", parsed.signatureValid);
if (!unsignedMode) {
  console.log("Signer id:", Buffer.from(parsed.signerId).toString("hex"));
  console.log("Pubkey    :", Buffer.from(parsed.pubkey).toString("hex"));
  const trust = FsParser.verifySignature(bytes, [store]);
  console.log("Publisher trusted (allowlist):", trust.trusted);
}

// Corruption test
const flipped = new Uint8Array(bytes);
flipped[Math.min(1000, bytes.length - 1)] ^= 0xff;
console.log("Bit flip -> hashValid:", FsParser.parse(flipped).hashValid);

// Tampering test (only meaningful when signed)
if (!unsignedMode) {
  const attacker = generateKeyPair();
  const forged = FsParser.serialize(roots, { seed: attacker.seed });
  console.log("Forged by another key -> trusted:", FsParser.verifySignature(forged, [store]).trusted);
}

console.log(parsed.roots[0].toString());