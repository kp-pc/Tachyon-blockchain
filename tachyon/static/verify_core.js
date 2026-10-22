/* Tachyon light-client proof core — single source of truth.
 *
 * Deliberately dependency-free and browser-safe: the phone client embeds this
 * exact text, and the Node test harness loads this exact file. There is no
 * second copy to drift out of sync.
 *
 * Wire contract (must match tachyon/encoding.py and tachyon/smt.py):
 *
 *   digest(tag, chunks...) = sha256("tachyon:v1:" + tag + 0x00 + chunks...)
 *
 * The 0x00 after the tag is easy to miss because it is invisible in terminal
 * output. Omitting it makes every proof fail to verify on the client while the
 * server keeps reporting the balance as valid.
 */
(function (global) {
  'use strict';

  var K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];

  function sha256(bytes) {
    var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    var l = bytes.length;
    if (l >= (1 << 29)) throw new Error('input too long');
    var bitLen = l * 8;
    var padded = new Uint8Array((((l + 9) + 63) >> 6) << 6);
    padded.set(bytes);
    padded[l] = 0x80;
    new DataView(padded.buffer).setUint32(padded.length - 4, bitLen >>> 0, false);
    var W = new Uint32Array(64);
    var dv = new DataView(padded.buffer);
    function R(x, n) { return (x >>> n) | (x << (32 - n)); }
    for (var off = 0; off < padded.length; off += 64) {
      for (var i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4, false);
      for (var j = 16; j < 64; j++) {
        var s0 = R(W[j-15],7) ^ R(W[j-15],18) ^ (W[j-15] >>> 3);
        var s1 = R(W[j-2],17) ^ R(W[j-2],19) ^ (W[j-2] >>> 10);
        W[j] = (W[j-16] + s0 + W[j-7] + s1) >>> 0;
      }
      var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
      for (var k = 0; k < 64; k++) {
        var S1 = R(e,6) ^ R(e,11) ^ R(e,25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[k] + W[k]) >>> 0;
        var S0 = R(a,2) ^ R(a,13) ^ R(a,22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) >>> 0;
        h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
      }
      H[0]=(H[0]+a)>>>0;H[1]=(H[1]+b)>>>0;H[2]=(H[2]+c)>>>0;H[3]=(H[3]+d)>>>0;
      H[4]=(H[4]+e)>>>0;H[5]=(H[5]+f)>>>0;H[6]=(H[6]+g)>>>0;H[7]=(H[7]+h)>>>0;
    }
    var out = new Uint8Array(32);
    var odv = new DataView(out.buffer);
    for (var m = 0; m < 8; m++) odv.setUint32(m * 4, H[m], false);
    return out;
  }

  var DOMAIN = [116,97,99,104,121,111,110,58,118,49,58]; // "tachyon:v1:"

  function asciiBytes(s) {
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
    return out;
  }

  function utf8Bytes(s) {
    var out = [], i, c;
    for (i = 0; i < s.length; i++) {
      c = s.charCodeAt(i);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return new Uint8Array(out);
  }

  function concat(parts) {
    var total = 0, i;
    for (i = 0; i < parts.length; i++) total += parts[i].length;
    var out = new Uint8Array(total), at = 0;
    for (i = 0; i < parts.length; i++) { out.set(parts[i], at); at += parts[i].length; }
    return out;
  }

  function digest(tag) {
    var parts = [new Uint8Array(DOMAIN), asciiBytes(tag), new Uint8Array([0])];
    for (var i = 1; i < arguments.length; i++) parts.push(arguments[i]);
    return sha256(concat(parts));
  }

  var EMPTY_LEAF = digest('smt:leaf', new Uint8Array(0));

  function balanceKey(address) { return utf8Bytes('balance:' + address); }
  function balanceSlot(address) { return digest('state_slot', balanceKey(address)); }

  function hexToBytes(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return null;
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function bytesToHex(b) {
    var s = '', i;
    for (i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
    return s;
  }

  function verifyBalance(address, proof, stateRootHex) {
    if (!proof || typeof proof !== 'object') return { ok: false, reason: 'proof must be an object', balance: null };

    var slot = hexToBytes(proof.slot);
    if (!slot || slot.length !== 32) return { ok: false, reason: 'proof.slot must be 32 bytes of hex', balance: null };

    var expected = balanceSlot(address);
    if (bytesToHex(slot) !== bytesToHex(expected)) {
      return { ok: false, reason: 'proof is for a different state slot', balance: null };
    }

    if (!Array.isArray(proof.branch) || proof.branch.length !== 256) {
      return { ok: false, reason: 'proof.branch must have 256 entries', balance: null };
    }

    var value = null;
    if (proof.value !== null && proof.value !== undefined) {
      value = hexToBytes(proof.value);
      if (!value) return { ok: false, reason: 'proof.value must be even-length hex or null', balance: null };
    }

    var current = value === null ? EMPTY_LEAF : digest('smt:leaf', slot, value);

    for (var i = 0; i < 256; i++) {
      var sibling = hexToBytes(proof.branch[i]);
      if (!sibling || sibling.length !== 32) {
        return { ok: false, reason: 'proof.branch[' + i + '] must be 32 bytes of hex', balance: null };
      }
      var bit = (slot[31 - (i >> 3)] >> (i & 7)) & 1;
      current = bit === 0 ? digest('smt:node', current, sibling) : digest('smt:node', sibling, current);
    }

    var root = hexToBytes(stateRootHex);
    if (!root || root.length !== 32) return { ok: false, reason: 'state_root must be 32 bytes of hex', balance: null };
    if (bytesToHex(current) !== bytesToHex(root)) {
      return { ok: false, reason: 'proof does not fold to the given state root', balance: null };
    }

    var balance = 0;
    if (value !== null) for (var v = 0; v < value.length; v++) balance = balance * 256 + value[v];
    return { ok: true, reason: 'ok', balance: balance };
  }

  global.TachyonVerify = {
    sha256: sha256,
    digest: digest,
    balanceKey: balanceKey,
    balanceSlot: balanceSlot,
    verifyBalance: verifyBalance,
    bytesToHex: bytesToHex,
    hexToBytes: hexToBytes
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
