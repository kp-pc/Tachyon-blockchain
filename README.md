<div align="center">

# ⚡ Tachyon
### A From-Scratch High-Performance Blockchain

![Python](https://img.shields.io/badge/Python-3.12+-blue) ![Dependencies](https://img.shields.io/badge/Dependencies-none-success) ![Consensus](https://img.shields.io/badge/Consensus-Stake--Weighted%20BFT-green) ![Status](https://img.shields.io/badge/Status-Experimental-orange)

**Tachyon** is a pure-Python, dependency-free blockchain exploring high-throughput designs inspired by **Solana**, **Aptos**, **Sui** and **Tendermint** — with a mobile-friendly fair-play mining layer.

</div>

---

## 🚀 Key Features

| Feature | Description | Inspiration |
|---|---|---|
| **⚡ 6-Stage Pipeline** | Fetch → Gossip → Verify → Execute → Store → Finalize, each stage decoupled for backpressure and latency hiding. | Solana |
| **🏃 Optimistic Parallel Execution** | Block-STM style speculative execution with read/write sets and conflict re-execution. | Aptos / Sui |
| **🔒 Ed25519 (RFC 8032)** | Pure-Python signatures with a precomputed base-point table (~0.5 ms sign, ~1.5 ms verify). No third-party crypto. | Modern BFT |
| **🌲 Sparse Merkle Tree** | 256-bit sparse state tree with compact inclusion and exclusion proofs; precomputed empty-subtree hashes. | Cosmos / Zcash |
| **⚖️ Stake-Weighted BFT** | Deterministic round-robin leader election and >2/3 stake quorum finality with append-only vote log. | Tendermint |
| **💸 EIP-1559 Fee Market** | Base fee adjusts per block against a utilization target, clamped to ±10% change. | Ethereum |
| **📱 ARM-Friendly Fair Play** | Tier-scaled PoW difficulty so phones and servers win blocks at comparable rates. | — |

---

## 📱 Mobile & ARM Support

Tachyon is designed to be **lightweight and ARM-friendly**. The `pow` module implements a **Fair Play** difficulty engine:

- **Tier-scaled targets** — a mobile (ARM) miner solves a much easier puzzle than a server, so both find blocks on a comparable timescale despite wildly different hash power.
- **Tier-balanced quorum** — `FairPlayEngine.check_quorum` requires each *registered* hardware tier to contribute its share of votes, so servers cannot drown out mobile participants. Tiers with no registered miners are skipped.
- **Battery-aware design** — the hash loop is plain SHA-256 (no SHA-NI assumptions) and yields to the OS periodically to avoid pinning a phone core.

```bash
python -m tachyon.pow        # fair-play mining demo: ARM phone vs x86 server
```

---

## 📅 Development Timeline

### ✅ Phase 1 — Core Architecture (Achieved)

- [x] **Cryptographic foundation** — Ed25519 (RFC 8032) with precomputed base table, base58 addresses with checksums, domain-separated SHA-256 for every hash context.
- [x] **State management** — Sparse Merkle Tree with inclusion/exclusion proofs and precomputed empty hashes.
- [x] **Consensus engine** — stake-weighted BFT finality (>2/3), slot clock (400 ms), 6-stage pipelined block processor.
- [x] **Transaction management** — priority mempool and EIP-1559-style dynamic base fee.
- [x] **Verification tooling** — RFC 8032 vectors, end-to-end simulation, throughput benchmark.

### ✅ Phase 2 — Mobile Fairness (Achieved)

- [x] **ARM-friendly PoW layer** — `pow.py` tier system with per-tier difficulty targets and nonce verification.
- [x] **Fair-play quorum** — `mobile.py` enforces per-tier vote shares instead of raw hash-power dominance.

### 🚧 Phase 3 — Scaling & Real-World Use (Planned)

- [ ] **VRF leader election** — replace round-robin with verifiable randomness for unpredictable slot assignment.
- [ ] **Smart contracts** — sandboxed deterministic execution environment (WASM or restricted bytecode).
- [ ] **Gossip tuning** — sub-100 ms block propagation across geographically distributed nodes.
- [ ] **Light client proofs** — ship SMT exclusion/inclusion proofs over JSON-RPC for mobile verifiers.
- [ ] **Cross-chain bridging** — interoperability with existing BFT chains.

---

## 📊 Performance Benchmarks

Measured with `scripts/benchmark.py` (10 blocks, 3 transactions per block, full Ed25519 signing and verification plus SMT updates):

```
Transactions Per Second (tx/s) by Validator Count
--------------------------------------------------------------
 2 Validators:  1070.08 tx/s ####################################   |
 4 Validators:   949.37 tx/s #############################          |
 8 Validators:  1166.17 tx/s ####################################   |
16 Validators:  1070.04 tx/s ####################################   |
--------------------------------------------------------------
```

Numbers are single-process simulation results on a 12-core container, not network throughput.

---

## 🛠️ Getting Started

**Requirements:** Python 3.12+ — no third-party packages.

```bash
git clone https://github.com/kp-pc/Tachyon-blockchain.git
cd Tachyon-blockchain
```

| Task | Command |
|---|---|
| End-to-end simulation | `python -m tachyon.simulation` |
| Throughput benchmark | `python scripts/benchmark.py` |
| Fair-play mining demo | `python -m tachyon.pow` |
| RFC 8032 crypto vectors | `python tests/test_crypto.py` |

---

## 📂 Project Structure

```text
tachyon/
├── encoding.py    # base58, canonical JSON, domain-separated hashing
├── crypto.py      # Ed25519 (RFC 8032) + address derivation
├── merkle.py      # binary Merkle tree with inclusion proofs
├── smt.py         # Sparse Merkle Tree state commitment
├── chain.py       # blocks, transactions, votes, ledger, BFT finality
├── pipeline.py    # 6-stage block processing pipeline
├── executor.py    # optimistic parallel execution (Block-STM style)
├── feemarket.py   # EIP-1559-style base fee
├── mempool.py     # priority transaction pool
├── election.py    # round-robin and stake-weighted leader election
├── pow.py         # ARM-friendly fair-play PoW layer
├── mobile.py      # tier-balanced quorum engine
├── storage.py     # append-only ledger persistence
├── networking.py  # peer gossip
├── rpc.py         # JSON-RPC server
└── cli.py         # command-line client

scripts/benchmark.py        # throughput charts
tests/test_crypto.py        # RFC 8032 vectors
```

---

## ⚠️ Security Disclaimer

Tachyon is an **educational and research** project. The consensus and cryptographic code has not been audited. Do not use it to transfer real value.

---

## 🤝 Contributing

Issues and pull requests are welcome — especially around VRF election, smart-contract sandboxing, and light-client proofs.

<div align="center">

**Tachyon** — built from scratch in pure Python

</div>
