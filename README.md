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

---

## 📱 Mining from an Android Phone

A phone cannot mine like a server. Android kills background CPU work (API 26+),
thermal throttling cuts hash rate within minutes, and a 24/7 hash loop flattens
the battery. So Tachyon uses **bounded work tickets**, not continuous mining.

```
phone                          pool
  |-- calibrate local hash rate -->|
  |                               |-- pick difficulty for ~3s of work on THIS device
  |<------ signed ticket ---------|
  |-- hash for a few seconds -----|
  |------- submit nonce --------->|-- verify signature, expiry, single-use
  |                               |-- credit weight = 2^difficulty
  |<-------- accepted ------------|-- assemble a block when weight threshold is hit
```

The ticket is HMAC-signed, so a client cannot rewrite `difficulty` downward to
claim credit for work it never did. Tickets are single-use, expire after 90s, and
submissions get a 15s grace window so a phone that solved just before expiry is
not punished for cellular latency.

**Why this gives phones a fair shot:** credit is `2^difficulty` per share. A phone
solves an easier ticket and earns 32,768; a server solves a harder one and earns
1,048,576. The server earns more in absolute terms -- it did more work -- but
neither tier is cheated on payout *per hash*. The pool aggregates millions of
small shares into blocks so a phone participates meaningfully.

### Run a pool (on the machine with the chain)

```bash
python -m tachyon.mobile_server --port 8080
```

Or programmatically:

```python
from tachyon.mobile_server import MiningServer
import time
s = MiningServer(port=8080)
s.start()
time.sleep(3600)
```

### Option A -- open it in the phone browser (no install)

Browse to `http://<pool-ip>:8080/` on the phone. The page ships an inline
synchronous SHA-256 (WebCrypto is async-per-call and ~100x too slow to drive a
hash loop), calls the pool over `fetch`, and shows hash rate, difficulty,
expected solve time and accumulated credit. Stop it any time; nothing is
installed and no background service is registered.

### Option B -- Termux CLI miner

```bash
pkg install python
python scripts/mobile_mine.py --pool http://192.168.1.20:8080 --miner my-phone --tier 1
```

Same bounded loop: calibrate, request ticket, hash, submit, rest.

### Pool endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/register` | `{miner, tier}` -> account |
| POST | `/ticket` | `{miner, tier, hashes_per_second}` -> signed ticket |
| POST | `/share` | `{ticket, nonce, elapsed_ms}` -> credit |
| GET | `/status` | pool totals, accepted/rejected, blocks assembled |
| GET | `/leaderboard` | ranked miners by credit |
| GET | `/` | the embedded phone client |

### Before exposing a pool beyond localhost

1. Terminate TLS in front of it -- plain HTTP leaks tickets, and a sniffed ticket can be raced.
2. Rate limit `/ticket` and `/share` per IP, or one client can drain the pool's CPU.
3. Persist consumed ticket ids; a restart makes old tickets replayable within their TTL.
4. Raise `BLOCK_WEIGHT_THRESHOLD`; the default is sized for demos.

The server never leaks stack traces to clients and caps request bodies at 64 KB.


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
├── mobile_protocol.py  # signed work tickets, calibration, hash contract
├── mobile_pool.py      # share accounting and block assembly
├── mobile_server.py    # HTTP transport + embedded phone client
├── storage.py     # append-only ledger persistence
├── networking.py  # peer gossip
├── rpc.py         # JSON-RPC server
└── cli.py         # command-line client

scripts/benchmark.py        # throughput charts
scripts/mobile_mine.py      # Termux/Android CLI miner
tests/test_crypto.py        # RFC 8032 vectors
tests/test_mobile.py        # mobile protocol, pool, HTTP (53 checks)
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
