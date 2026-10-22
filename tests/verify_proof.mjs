// CLI wrapper around tachyon/static/verify_core.js.
//
// The verifier logic lives in exactly one place so the browser client and this
// harness cannot drift. Drift is not hypothetical: the 0x00 separator after the
// hash domain tag was once missing here, which made every proof fail on the
// client while the server happily reported a valid balance.
//
// Usage: node tests/verify_proof.mjs '<json>'
//   json = {address, state_root, proof:{slot,value,branch}}
// Prints JSON: {ok, reason, balance}

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const corePath = join(here, '..', 'tachyon', 'static', 'verify_core.js');

// The core is a classic script that attaches TachyonVerify to the global.
new Function(readFileSync(corePath, 'utf8'))();
const { verifyBalance } = globalThis.TachyonVerify;

const input = process.argv[2];
if (!input) {
  console.error('usage: node tests/verify_proof.mjs <json>');
  process.exit(2);
}

let parsed;
try {
  parsed = JSON.parse(input);
} catch (err) {
  console.log(JSON.stringify({ ok: false, reason: 'invalid json: ' + err.message, balance: null }));
  process.exit(1);
}

const result = verifyBalance(parsed.address, parsed.proof, parsed.state_root);
console.log(JSON.stringify(result));
process.exit(result.ok ? 0 : 1);
