/**
 * Pure JS Ed25519 (RFC 8032) + SHA-512 — no dependencies, sync, works in Node and browser.
 * Verified against Node.js crypto in tests (interop sign/verify both directions).
 */

const MASK64 = (1n << 64n) - 1n;

// ---- SHA-512 (BigInt-based, correct but not fast — fine for signing) ----
const SHA512_K = [
  0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
  0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
  0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
  0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
  0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
  0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
  0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
  0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
  0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
  0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n
];

const SHA512_H0 = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n
];

function sha512_rotr(x, n) {
  return ((x >> n) | (x << (64n - n))) & MASK64;
}

/**
 * @param {Uint8Array} data
 * @returns {Uint8Array} 64-byte SHA-512
 */
function sha512(data) {
  const w = new Array(80).fill(0n);
  const h = SHA512_H0.slice();

  const l = data.length;
  const bitLen = BigInt(l) * 8n;

  let paddedLen = (((l + 16) >> 7) + 1) << 7;
  const msg = new Uint8Array(paddedLen);
  msg.set(data);
  msg[l] = 0x80;
  const dv = new DataView(msg.buffer);
  dv.setBigUint64(paddedLen - 8, bitLen, false);

  let a, b, c, d, e, f, g, hh, s0, s1, t1, t2, ch, maj;

  for (let i = 0; i < paddedLen; i += 128) {
    for (let t = 0; t < 16; t++) w[t] = dv.getBigUint64(i + t * 8, false);

    for (let t = 16; t < 80; t++) {
      s0 = sha512_rotr(w[t - 15], 1n) ^ sha512_rotr(w[t - 15], 8n) ^ (w[t - 15] >> 7n);
      s1 = sha512_rotr(w[t - 2], 19n) ^ sha512_rotr(w[t - 2], 61n) ^ (w[t - 2] >> 6n);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & MASK64;
    }

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];

    for (let t = 0; t < 80; t++) {
      s1 = sha512_rotr(e, 14n) ^ sha512_rotr(e, 18n) ^ sha512_rotr(e, 41n);
      ch = (e & f) ^ (~e & g);
      t1 = (hh + s1 + ch + SHA512_K[t] + w[t]) & MASK64;
      s0 = sha512_rotr(a, 28n) ^ sha512_rotr(a, 34n) ^ sha512_rotr(a, 39n);
      maj = (a & b) ^ (a & c) ^ (b & c);
      t2 = (s0 + maj) & MASK64;

      hh = g; g = f; f = e; e = (d + t1) & MASK64;
      d = c; c = b; b = a; a = (t1 + t2) & MASK64;
    }

    h[0] = (h[0] + a) & MASK64;
    h[1] = (h[1] + b) & MASK64;
    h[2] = (h[2] + c) & MASK64;
    h[3] = (h[3] + d) & MASK64;
    h[4] = (h[4] + e) & MASK64;
    h[5] = (h[5] + f) & MASK64;
    h[6] = (h[6] + g) & MASK64;
    h[7] = (h[7] + hh) & MASK64;
  }

  const out = new Uint8Array(64);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setBigUint64(i * 8, h[i], false);
  return out;
}

// ---- Ed25519 curve (RFC 8032) ----
const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
const I = modpow(2n, (P - 1n) / 4n, P);

function modpow(a, e, m) {
  let result = 1n;
  a = ((a % m) + m) % m;
  while (e > 0n) {
    if (e & 1n) result = (result * a) % m;
    a = (a * a) % m;
    e >>= 1n;
  }
  return result;
}

function mod(a, m) { return ((a % m) + m) % m; }

const Bx = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
const By = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;

// Extended coordinates (X, Y, Z, T): x=X/Z, y=Y/Z, x*y=T/Z
function pointAdd(p1, p2) {
  const [X1, Y1, Z1, T1] = p1;
  const [X2, Y2, Z2, T2] = p2;
  const A = mod((Y1 - X1) * (Y2 - X2), P);
  const B = mod((Y1 + X1) * (Y2 + X2), P);
  const C = mod(T1 * 2n * D * T2, P);
  const DD = mod(Z1 * 2n * Z2, P);
  const E = mod(B - A, P);
  const F = mod(DD - C, P);
  const G = mod(DD + C, P);
  const H = mod(B + A, P);
  return [mod(E * F, P), mod(G * H, P), mod(F * G, P), mod(E * H, P)];
}

function pointDouble(p1) {
  const [X1, Y1, Z1] = p1;
  const A = mod(X1 * X1, P);
  const B = mod(Y1 * Y1, P);
  const C = mod(2n * Z1 * Z1, P);
  const D = mod(-A, P);
  const E = mod((X1 + Y1) * (X1 + Y1) - A - B, P);
  const G = mod(D + B, P);
  const F = mod(G - C, P);
  const H = mod(D - B, P);
  return [mod(E * F, P), mod(G * H, P), mod(F * G, P), mod(E * H, P)];
}

function pointMult(k, point) {
  // 4-bit window: precompute multiples 0..15
  const table = [null, point, pointDouble(point)];
  table[3] = pointAdd(table[1], table[2]);
  table[4] = pointDouble(table[2]);
  for (let i = 5; i <= 15; i++) table[i] = pointAdd(table[4], table[i - 4]);

  let result = [0n, 1n, 1n, 0n]; // identity
  for (let i = 63; i >= 0; i--) {
    // shift left by 4 bits (multiply by 16) before adding the nibble
    result = pointDouble(pointDouble(pointDouble(pointDouble(result))));
    const nibble = Number((k >> BigInt(i * 4)) & 0xfn);
    if (nibble) result = pointAdd(result, table[nibble]);
  }
  return result;
}

function pointEqual(p1, p2) {
  return mod(p1[0] * p2[2], P) === mod(p2[0] * p1[2], P) &&
         mod(p1[1] * p2[2], P) === mod(p2[1] * p1[2], P);
}

function pointFromBytes(data) {
  // data: 32-byte compressed point: y (255 bits LE) | sign bit (bit 255)
  let val = 0n;
  for (let i = 31; i >= 0; i--) val = (val << 8n) | BigInt(data[i]);
  const xSign = (val >> 255n) & 1n;
  const y = val & ((1n << 255n) - 1n);
  if (y >= P) return null;

  const y2 = mod(y * y, P);
  const u = mod(y2 - 1n, P);
  const v = mod(D * y2 + 1n, P);
  // RFC 8032: p ≡ 5 (mod 8), x = u*v^3*(u*v^7)^((p-5)/8)
  let x = mod(u * modpow(v, 3n, P) * modpow(mod(u * modpow(v, 7n, P), P), (P - 5n) / 8n, P), P);

  if (mod(v * x * x, P) !== u) {
    x = mod(x * I, P); // multiply by sqrt(-1)
    if (mod(v * x * x, P) !== u) return null;
  }
  if ((x & 1n) !== xSign) x = mod(-x, P);
  return [x, y, 1n, mod(x * y, P)];
}

function pointToBytes(point) {
  const [X, Y, Z] = point;
  const zi = modpow(Z, P - 2n, P);
  const x = mod(X * zi, P);
  const y = mod(Y * zi, P);

  const out = new Uint8Array(32);
  let yy = y;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(yy & 0xffn);
    yy >>= 8n;
  }
  out[31] |= (x & 1n) ? 0x80 : 0;
  return out;
}

function bytesToHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

const encLength = 32;
const dsaSignatureLength = 64;

// Prune the sc_reduce-like secret scalar
function pruneScalar(h) {
  const a = h.slice(0, 32);
  a[0] &= 248;
  a[31] &= 127;
  a[31] |= 64;
  return a;
}

/**
 * Generate a key pair.
 * @returns {{ seed: Uint8Array, publicKey: Uint8Array }}
 */
function generateKeyPair(rng = typeof crypto !== "undefined" && crypto.getRandomValues
    ? (n) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
    : () => { throw new Error("No RNG available"); }) {
  const seed = rng(32);
  const publicKey = publicKeyFromSeed(seed);
  return { seed, publicKey };
}

function publicKeyFromSeed(seed) {
  const h = sha512(seed);
  const a = leScalar(pruneScalar(h));
  const A = pointMult(a, OWN_BASE);
  return pointToBytes(A);
}

// Interpret 32 bytes as a little-endian integer
function leScalar(bytes) {
  let s = 0n;
  for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(bytes[i]);
  return s;
}

function hashToScalar(bytes) {
  // RFC 8032: interpret full hash output as little-endian integer, reduce mod L
  const h = sha512(bytes);
  let s = 0n;
  for (let i = 63; i >= 0; i--) s = (s << 8n) | BigInt(h[i]);
  return s % L;
}

function basePoint() {
  const b = new Uint8Array(32);
  let y = By;
  for (let i = 0; i < 32; i++) {
    b[i] = Number(y & 0xffn);
    y >>= 8n;
  }
  b[31] |= (Bx & 1n) ? 0x80 : 0;
  return pointFromBytes(b);
}

const OWN_BASE = basePoint();

/**
 * Sign a message.
 * @param {Uint8Array} message
 * @param {Uint8Array} seed 32-byte private seed
 * @returns {{ signature: Uint8Array, publicKey: Uint8Array }} 64-byte signature
 */
function sign(message, seed) {
  const h = sha512(seed);
  const a = leScalar(pruneScalar(h));
  const prefix = h.slice(32);
  const BASE = OWN_BASE;

  const rMsg = new Uint8Array(prefix.length + message.length);
  rMsg.set(prefix);
  rMsg.set(message, prefix.length);
  const r = hashToScalar(rMsg);

  const R = pointMult(r, BASE);
  const REnc = pointToBytes(R);

  const AEnc = publicKeyFromSeed(seed);

  const kMsg = new Uint8Array(encLength + encLength + message.length);
  kMsg.set(REnc);
  kMsg.set(AEnc, encLength);
  kMsg.set(message, 2 * encLength);
  const k = hashToScalar(kMsg);

  const S = mod(r + k * a, L);
  const SEnc = new Uint8Array(32);
  let s = S;
  for (let i = 0; i < 32; i++) {
    SEnc[i] = Number(s & 0xffn);
    s >>= 8n;
  }

  const signature = new Uint8Array(dsaSignatureLength);
  signature.set(REnc);
  signature.set(SEnc, encLength);
  return { signature, publicKey: AEnc };
}

/**
 * Verify an Ed25519 signature (standard RFC 8032, cofactored).
 * @param {Uint8Array} message
 * @param {Uint8Array} signature 64 bytes
 * @param {Uint8Array} publicKey 32 bytes
 * @returns {boolean}
 */
function verify(message, signature, publicKey) {
  if (publicKey.length !== encLength) return false;
  if (signature.length !== dsaSignatureLength) return false;

  const A = pointFromBytes(publicKey);
  const R = pointFromBytes(signature.slice(0, 32));
  if (A === null || R === null) return false;

  let S = 0n;
  for (let i = 31; i >= 0; i--) S = (S << 8n) | BigInt(signature[32 + i]);
  if (S >= L) return false;

  const kMsg = new Uint8Array(64 + message.length);
  kMsg.set(signature.slice(0, 32));
  kMsg.set(publicKey, 32);
  kMsg.set(message, 64);
  const k = hashToScalar(kMsg);

  // [S]B = R + [k]A
  const SB = pointMult(S, OWN_BASE);
  const kA = pointMult(k, A);
  const expected = pointAdd(R, kA);
  return pointEqual(SB, expected);
}

// Node.js export
if (typeof module !== "undefined") {
  module.exports = {
    sha512, sign, verify, generateKeyPair,
    publicKeyFromSeed_ed25519: publicKeyFromSeed,
    sign_ed25519: sign
  };
}

// Browser/global (parser.js expects window.Ed25519 with { pubkey, sign, verify })
if (typeof window !== "undefined") {
  window.Ed25519 = {
    sha512,
    pubkey: publicKeyFromSeed,
    sign,
    verify,
    generateKeyPair
  };
}