# Changelog

All notable changes to Tachyon are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed — claims that were not true yet

Two features were advertised before they were real. Both are now implemented and
tested rather than merely documented.

- **State actually commits through the Sparse Merkle Tree.** `State` previously
  computed a plain Merkle root over sorted key/value digests and `smt.py` was
  never imported by `chain.py`. `State` now maintains a real `SparseMerkleTree`,
  derives a 256-bit slot per application key, and exposes `prove()` for
  inclusion (key present) and exclusion (key absent) proofs.
- **SMT keys are fixed at 32 bytes.** `int.from_bytes` mapped `b"\x01"` and
  `b"\x00\x01"` to the same index, so a variable-length key silently
  overwrote another key's leaf and broke its proof. Mixed lengths are now
  rejected with `ValueError` instead of corrupting state.
- **Pooled shares produce real blocks.** `MobilePool` incremented a
  `blocks_assembled` counter without ever constructing a `Block`. The new
  `mobile_chain.BlockAssembler` builds genuine `BlockHeader`/`Block` values with
  correct `parent_slot`/`parent_hash` linkage, one reward `Transaction` per
  credited miner, a `transactions_root` over that set, and a `state_root` equal
  to the SMT root after crediting.
- Miner balances are committed into SMT-backed state, so a balance is provable
  against a block header's `state_root`, and `verify_chain()` detects tampering
  of either `parent_hash` or `transactions_root`.

### Added — tests

- `tests/test_mobile_chain.py` — 59 checks over SMT proofs, key-length
  rejection, order independence, State commitment, assembler linkage, balance
  proofs and tamper detection.


### Added — Mining from Android phones

- `tachyon/mobile_protocol.py` — bounded work tickets. A phone measures its own
  hash rate, the pool sizes difficulty so the expected solve is ~3s, and tickets
  are HMAC-signed so a client cannot lower its own difficulty. Work contract is
  plain `sha256(seed || nonce_be8)` so a browser or Kotlin client can reproduce
  it exactly.
- `tachyon/mobile_pool.py` — share accounting with `2^difficulty` credit,
  single-use ticket replay protection, a 15s submit grace window for cellular
  latency, adaptive difficulty from observed solve times, and block assembly
  once accumulated share weight crosses a threshold.
- `tachyon/mobile_server.py` — stdlib HTTP transport plus an embedded phone
  client page. Ships an inline synchronous SHA-256 because WebCrypto is
  async-per-call and far too slow to drive a hash loop. Body cap 64 KB, no stack
  traces leaked to clients.
- `scripts/mobile_mine.py` — Termux/Android CLI miner using the same bounded
  loop.
- `tests/test_mobile.py` — 53 checks across protocol, pool and HTTP layers.

### Verified

- The inline JavaScript SHA-256 matches Python byte for byte across 8 nonces and
  the target comparison agrees at every difficulty 8-32, including the
  non-byte-aligned values where an off-by-one would silently break every phone.
- Live CLI miner against a running pool: 4 rounds, 4 shares accepted, 4 blocks
  assembled, 0 rejections.
- Forged difficulty, replay, expired ticket, non-solving nonce, malformed ticket,
  bad JSON, oversized body and unknown route are all rejected as intended.

### Known limitations

- No TLS and no per-IP rate limiting yet; the module documents what production
  requires.
- Consumed ticket ids are in memory, so a pool restart makes unexpired tickets
  replayable within their TTL.
- A phone with a throttled CPU gets easier tickets, not equal say in consensus --
  credit fairness is per-hash payout, not voting power.

## [0.1.0] - 2026-10-22

First public release. Tachyon is an **experimental, unaudited** research
blockchain. Nothing here is suitable for transferring real value.

### Added — Cryptographic foundation

- Pure-Python Ed25519 (`tachyon/crypto.py`) implementing RFC 8032 with a
  64-entry precomputed base-point table. Measured ~0.5 ms sign and ~1.5 ms
  verify per operation in this container.
- Base58 addresses with a 4-byte checksum and `tch` prefix.
- Domain-separated SHA-256 hashing (`tachyon/encoding.py`) so digests from
  different contexts cannot collide by construction.
- Canonical JSON encoding with sorted keys for deterministic signed payloads.
- Binary Merkle tree with inclusion proofs (`tachyon/merkle.py`), domain
  separated leaves/internal nodes and explicit leaf-count binding.

### Added — State

- Sparse Merkle Tree (`tachyon/smt.py`) with 256-bit keys, precomputed empty
  subtree hashes, and compact inclusion/exclusion proofs.

### Added — Chain and consensus

- Block headers, signed transactions, stake-weighted votes, and an in-memory
  ledger with append-only vote storage (`tachyon/chain.py`).
- Stake-weighted BFT finality requiring strictly greater than 2/3 of total
  stake, with a 400 ms slot clock.
- Six-stage block processing pipeline: fetch, gossip, verify, execute, store,
  finalize (`tachyon/pipeline.py`).
- Optimistic parallel executor with speculative read/write sets
  (`tachyon/executor.py`).
- EIP-1559-style base fee market clamped to 10% change per adjustment, with a
  1,000 lamport/CU floor (`tachyon/feemarket.py`).
- Round-robin and stake-weighted leader election (`tachyon/election.py`).
- Priority mempool (`tachyon/mempool.py`).

### Added — Mobile / ARM

- Tier-scaled proof-of-work difficulty (`tachyon/pow.py`) so mobile (ARM)
  participants solve an easier target than servers and still find blocks on a
  comparable timescale. Plain SHA-256 loop with periodic OS yields — no
  SHA-NI assumption.
- Tier-balanced quorum engine (`tachyon/mobile.py`): every registered hardware
  tier must contribute its vote share, so server hash power cannot drown out
  mobile participants. Unregistered tiers are skipped.

### Added — Interfaces and tooling

- Append-only ledger persistence (`tachyon/storage.py`).
- JSON-RPC server and command-line client (`tachyon/rpc.py`, `tachyon/cli.py`).
- Simple TCP peer gossip (`tachyon/networking.py`).
- End-to-end multi-validator simulation (`tachyon/simulation.py`).
- Throughput benchmark with ASCII chart (`scripts/benchmark.py`).
- RFC 8032 test vectors (`tests/test_crypto.py`).

### Verified in this release

- Ed25519 matches RFC 8032 vectors for seeds 1–3, and rejects tampered messages.
- Simulation chain integrity passes for 5/4, 10/4 and 20/8 block/validator
  configurations, including parent-hash linkage and finality slot assertions.
- Tier quorum accepts balanced votes and rejects a server-only vote set.
- Throughput measured between ~949 and ~1,166 transactions/second across 2–16
  validators in a single process on a 12-core container.

### Known limitations

- **Not audited.** No external security review of the crypto or consensus code.
- **Simulation, not a network.** Blocks and votes are produced in one process;
  the gossip and RPC layers are exercised separately, not as a live cluster.
- **Fair play is difficulty scaling, not proven hash-power equalisation.** A
  phone wins blocks because its target is easier, not because the math makes
  hash power equal.
- **PoW is a bolt-on.** Chain finality still comes from stake-weighted BFT in
  `chain.py`; the tier system is an optional participation mechanism, not in
  the consensus path.
- **No VRF election yet.** Leader selection is deterministic round-robin or a
  static weighted schedule, both predictable by an adversary.
- **No smart contracts.** Instructions are placeholders, not a sandbox.
- **Single-process performance only.** No networked throughput measured.
