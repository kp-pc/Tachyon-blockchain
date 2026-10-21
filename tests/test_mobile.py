"""Regression tests for the mobile mining path.

Run directly (no pytest dependency):

    python tests/test_mobile.py

Covers three layers that each fail silently in production if broken:
  1. protocol  -- hash contract, calibration, ticket signing, share validity
  2. pool      -- credit, replay, forgery, expiry, grace window
  3. http      -- real sockets, real JSON, real status codes
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tachyon.mobile_pool import MobilePool
from tachyon.mobile_protocol import (
    TicketIssuer,
    WorkTicket,
    calibrate_difficulty,
    difficulty_target,
    find_share,
    measure_hash_rate,
    share_is_valid,
    work_hash,
)
from tachyon.mobile_server import MiningServer

PASSED = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"FAILED: {name} {detail}")
    PASSED.append(name)
    print(f"  ok  {name}")


def test_protocol() -> None:
    print("\n[protocol]")
    seed = bytes(range(32))

    # The hash contract must be exactly sha256(seed || nonce_be8); the JS client
    # depends on this byte for byte.
    for nonce in (0, 1, 7, 2**32 - 1, 2**32, 2**40):
        expected = hashlib.sha256(seed + nonce.to_bytes(8, "big")).digest()
        check(f"work_hash matches sha256 at nonce={nonce}", work_hash(seed, nonce) == expected)

    check(
        "work_hash rejects short seed",
        _raises(lambda: work_hash(b"short", 0)),
    )
    check(
        "work_hash rejects out-of-range nonce",
        _raises(lambda: work_hash(seed, 1 << 64)),
    )

    # Calibration: difficulty d means ~2^d hashes, so time ~ 2^d / hps.
    for hps, seconds, lo, hi in (
        (50_000, 3.0, 16, 18),
        (200_000, 3.0, 18, 20),
        (2_000_000, 3.0, 21, 23),
        (1_000_000, 1.0, 19, 21),
    ):
        d = calibrate_difficulty(hps, seconds)
        check(f"calibrate({hps} h/s, {seconds}s) in [{lo},{hi}] -> {d}", lo <= d <= hi)

    check("calibrate rejects zero hash rate", _raises(lambda: calibrate_difficulty(0, 1.0)))
    check("difficulty_target rejects out-of-bounds", _raises(lambda: difficulty_target(33)))

    # Ticket signing
    issuer = TicketIssuer(target_seconds=0.3)
    ticket = issuer.issue("phone-1", tier=1, difficulty=14)
    ok, reason = issuer.verify(ticket)
    check("issued ticket verifies", ok, reason)

    forged = WorkTicket(**{**ticket.__dict__, "difficulty": 8})
    ok, reason = issuer.verify(forged)
    check("lowered difficulty is rejected", not ok and reason == "bad signature", reason)

    ok, reason = issuer.verify(ticket, now_ms=ticket.expires_at_ms + 1)
    check("expired ticket is rejected", not ok and reason == "ticket expired", reason)

    other = TicketIssuer(target_seconds=0.3)
    foreign = other.issue("phone-1", tier=1, difficulty=14)
    ok, reason = issuer.verify(foreign)
    check("ticket from another pool is rejected", not ok, reason)

    # Round trip through JSON (what actually crosses the wire)
    restored = WorkTicket.from_dict(json.loads(json.dumps(ticket.to_dict())))
    check("ticket JSON round-trip preserves signature", restored == ticket)
    check("ticket JSON round-trip still verifies", issuer.verify(restored)[0])

    # Share validity and a real solve
    solved = find_share(seed, 12, max_hashes=10_000_000)
    check("find_share returns a solution", solved is not None)
    if solved is not None:
        nonce, tried = solved
        check("solution meets target", share_is_valid(seed, nonce, 12))
        check("solution rejected under a wrong seed", not share_is_valid(bytes(32), nonce, 12))

    check("bounded search respects its budget", find_share(bytes(32), 24, max_hashes=200) is None)

    hps = measure_hash_rate(seed, sample_hashes=500)
    check(f"measure_hash_rate returns a positive rate ({hps:,.0f} h/s)", hps > 0)


class _raises:
    """Tiny context helper: true when the call raises."""

    def __init__(self, fn):
        self.fn = fn

    def __bool__(self):
        try:
            self.fn()
        except Exception:
            return True
        return False


def test_pool() -> None:
    print("\n[pool]")
    pool = MobilePool(target_seconds=0.2, block_weight_threshold=1 << 17)
    pool.register("phone", 1)

    ticket = pool.request_ticket("phone", 1, hashes_per_second=120_000)
    solved = find_share(ticket.seed, ticket.difficulty, max_hashes=20_000_000)
    check("pool ticket is solvable", solved is not None)
    nonce, tried = solved

    record = pool.submit_share(ticket.to_dict(), nonce, hashes_tried=tried, elapsed_ms=150)
    check("valid share is credited", record.credited, record.reason)
    check("credited weight equals 2**difficulty", record.weight == 1 << ticket.difficulty)

    replay = pool.submit_share(ticket.to_dict(), nonce)
    check("replay is rejected", not replay.credited and "already used" in replay.reason, replay.reason)

    t2 = pool.request_ticket("phone", 1, hashes_per_second=120_000)
    forged = {**t2.to_dict(), "difficulty": t2.difficulty + 8}
    solved2 = find_share(t2.seed, t2.difficulty, max_hashes=20_000_000)
    bad = pool.submit_share(forged, solved2[0])
    check("forged difficulty is rejected", not bad.credited and bad.reason == "bad signature", bad.reason)

    t3 = pool.request_ticket("phone", 1, hashes_per_second=120_000)
    wrong = pool.submit_share(t3.to_dict(), 987654321)
    check("non-solving nonce is rejected", not wrong.credited and "target" in wrong.reason, wrong.reason)

    t4 = pool.request_ticket("phone", 1, hashes_per_second=120_000)
    solved4 = find_share(t4.seed, t4.difficulty, max_hashes=20_000_000)
    late = pool.submit_share(t4.to_dict(), solved4[0], now_ms=t4.expires_at_ms + 20_000)
    check("ticket well past expiry is rejected", not late.credited and "expired" in late.reason, late.reason)

    t5 = pool.request_ticket("phone", 1, hashes_per_second=120_000)
    solved5 = find_share(t5.seed, t5.difficulty, max_hashes=20_000_000)
    just_late = pool.submit_share(t5.to_dict(), solved5[0], now_ms=t5.expires_at_ms + 5_000)
    check("submission inside the grace window is accepted", just_late.credited, just_late.reason)

    malformed = pool.submit_share({"nope": 1}, 5)
    check("malformed ticket is rejected without crashing", not malformed.credited)

    status = pool.status()
    # Exactly four rejections were attributed to this account: replay, forged
    # difficulty, non-solving nonce and expired ticket. The grace-window submit
    # was accepted, and the malformed-ticket submit returns before any account
    # is resolved, so it is intentionally not counted against a miner.
    check("status counts the four attributed rejections", status["shares_rejected"] == 4, str(status))
    check("status counts accepted shares", status["shares_accepted"] == 2, str(status))
    check("leaderboard lists the miner", any(r["miner"] == "phone" for r in pool.leaderboard()))


def test_http() -> None:
    print("\n[http]")
    server = MiningServer(pool=MobilePool(target_seconds=0.2), host="127.0.0.1", port=0)
    server.start()
    base = f"http://127.0.0.1:{server.port}"

    def get(path):
        try:
            with urllib.request.urlopen(base + path, timeout=5) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def post(path, obj=None, raw=None):
        data = raw if raw is not None else json.dumps(obj).encode()
        req = urllib.request.Request(
            base + path, data=data, method="POST", headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                return e.code, json.loads(body)
            except json.JSONDecodeError:
                return e.code, body

    try:
        code, body = get("/health")
        check("/health returns 200", code == 200)
        check("/health reports ok", json.loads(body)["ok"] is True)

        code, body = get("/")
        check("/ serves the phone client", code == 200 and b"Tachyon Mobile Miner" in body)

        code, body = post("/register", {"miner": "web-phone", "tier": 1})
        check("/register accepts a tier-1 miner", code == 200 and body["ok"])

        code, body = post("/ticket", {"miner": "web-phone", "tier": 1, "hashes_per_second": 100_000})
        check("/ticket returns a calibrated ticket", code == 200 and 14 <= body["ticket"]["difficulty"] <= 21)
        ticket = body["ticket"]

        solved = find_share(bytes.fromhex(ticket["seed"]), ticket["difficulty"], max_hashes=20_000_000)
        check("HTTP ticket is solvable", solved is not None)

        code, body = post("/share", {"ticket": ticket, "nonce": solved[0], "elapsed_ms": 90})
        check("/share credits a valid share", code == 200 and body["credited"] is True, str(body))

        code, body = post("/share", {"ticket": ticket, "nonce": solved[0]})
        check("/share rejects the replay", code == 200 and body["credited"] is False, str(body))

        code, body = get("/status")
        check("/status reports one accepted share", b'"shares_accepted": 1' in body)

        code, body = get("/leaderboard")
        check("/leaderboard lists the phone", b"web-phone" in body)

        code, _ = post("/ticket", raw=b"{this is not json")
        check("malformed JSON returns 400", code == 400)

        code, _ = post("/ticket", {"tier": 1})
        check("missing miner returns 400", code == 400)

        code, _ = post("/register", {"miner": "x", "tier": 3})
        check("invalid tier returns 400", code == 400)

        code, _ = get("/does-not-exist")
        check("unknown path returns 404", code == 404)

        oversized = b'{"miner":"' + b"a" * (70 * 1024) + b'"}'
        code, _ = post("/ticket", raw=oversized)
        check("oversized body returns 413", code == 413)
    finally:
        server.stop()

    check("server stopped cleanly", server._httpd is None)


def main() -> int:
    print("=" * 58)
    print("  TACHYON MOBILE MINING TESTS")
    print("=" * 58)
    test_protocol()
    test_pool()
    test_http()
    print("\n" + "=" * 58)
    print(f"  ALL {len(PASSED)} CHECKS PASSED")
    print("=" * 58)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
