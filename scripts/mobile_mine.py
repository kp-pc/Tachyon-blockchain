#!/usr/bin/env python3
"""Termux/Android CLI miner for a Tachyon mobile pool.

Runs on Android via Termux (pkg install python), on a Raspberry Pi, or on any
box that can reach the pool over HTTP. It performs the same bounded-work loop as
the embedded browser client: calibrate, request a ticket, hash for a few seconds,
submit, sleep, repeat.

Usage
-----
    python scripts/mobile_mine.py --pool http://192.168.1.20:8080 --miner my-phone
    python scripts/mobile_mine.py --pool http://host:8080 --miner pi --tier 2 --rounds 5

The ``--tier`` flag is advisory: the pool sizes difficulty from the hash rate you
report, so a phone naturally receives easier tickets than a server.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tachyon.mobile_protocol import find_share, measure_hash_rate


def post(pool: str, path: str, body: dict, timeout: float = 15.0) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        pool.rstrip("/") + path,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def get(pool: str, path: str, timeout: float = 15.0) -> dict:
    with urllib.request.urlopen(pool.rstrip("/") + path, timeout=timeout) as resp:
        return json.loads(resp.read())


def mine_loop(pool: str, miner: str, tier: int, rounds: int, rest: float, verbose: bool) -> int:
    try:
        health = get(pool, "/health")
    except (urllib.error.URLError, OSError) as exc:
        print(f"cannot reach pool {pool}: {exc}", file=sys.stderr)
        return 2
    print(f"connected to pool v{health.get('version', '?')} at {pool}")

    reg = post(pool, "/register", {"miner": miner, "tier": tier})
    print(f"registered as {reg.get('miner')} (tier {reg.get('tier')})")

    accepted = rejected = 0
    credit = 0
    completed = 0

    while rounds <= 0 or completed < rounds:
        completed += 1

        # Calibrate once per round: thermal throttling changes real hash rate.
        hps = measure_hash_rate(os.urandom(32), sample_hashes=4000)
        try:
            ticket = post(pool, "/ticket", {"miner": miner, "tier": tier, "hashes_per_second": hps})["ticket"]
        except (urllib.error.URLError, OSError, KeyError) as exc:
            print(f"ticket request failed: {exc}", file=sys.stderr)
            time.sleep(3)
            continue

        seed = bytes.fromhex(ticket["seed"])
        difficulty = int(ticket["difficulty"])
        expected = (1 << difficulty) / max(hps, 1.0)
        if verbose:
            print(
                f"round {completed}: {hps/1000:.0f}k h/s, difficulty {difficulty}, "
                f"expected ~{expected:.1f}s"
            )

        deadline = time.monotonic() + max(1.0, min(9.0, ticket["expires_at_ms"] / 1000.0 - time.time()))
        start = time.monotonic()
        result = find_share(seed, difficulty, deadline_monotonic=deadline)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        if result is None:
            print(f"round {completed}: no share before deadline ({elapsed_ms}ms), resting")
            time.sleep(rest)
            continue

        nonce, tried = result
        try:
            resp = post(pool, "/share", {"ticket": ticket, "nonce": nonce, "elapsed_ms": elapsed_ms})
        except (urllib.error.URLError, OSError) as exc:
            print(f"share submit failed: {exc}", file=sys.stderr)
            time.sleep(3)
            continue

        if resp.get("credited"):
            accepted += 1
            credit += int(resp.get("weight", 0))
            print(
                f"round {completed}: ACCEPTED nonce={nonce} ({tried:,} hashes, {elapsed_ms}ms) "
                f"weight={resp.get('weight'):,} total_credit={credit:,}"
            )
        else:
            rejected += 1
            print(f"round {completed}: rejected - {resp.get('reason')}")

        time.sleep(rest)

    print(f"\ndone: {accepted} accepted, {rejected} rejected, total credit {credit:,}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Tachyon mobile pool CLI miner")
    parser.add_argument("--pool", required=True, help="pool base URL, e.g. http://192.168.1.20:8080")
    parser.add_argument("--miner", default=None, help="miner name (default: device hostname)")
    parser.add_argument("--tier", type=int, default=1, choices=[1, 2, 4, 8], help="hardware tier (1=phone)")
    parser.add_argument("--rounds", type=int, default=0, help="stop after N rounds (0 = forever)")
    parser.add_argument("--rest", type=float, default=1.0, help="seconds to rest between rounds")
    parser.add_argument("--quiet", action="store_true", help="less output")
    args = parser.parse_args()

    miner = args.miner or f"phone-{os.uname().nodename[:10] if hasattr(os, 'uname') else 'android'}"
    try:
        return mine_loop(args.pool, miner, args.tier, args.rounds, args.rest, not args.quiet)
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
