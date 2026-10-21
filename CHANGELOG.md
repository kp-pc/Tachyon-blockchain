# Changelog

All notable changes to Tachyon are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
