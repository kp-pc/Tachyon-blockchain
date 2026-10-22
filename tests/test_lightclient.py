"""Light-client balance-proof tests, including a JavaScript cross-check.

Run directly (no pytest dependency):

    python tests/test_lightclient.py

The cross-check matters more than it looks. The mobile client verifies proofs in
JavaScript, so a disagreement between the two implementations means phones either
reject valid balances or accept forgeries. One such disagreement was found during
development: `encoding.digest()` appends a NUL byte after the tag, which is
invisible in terminal output. Omitting it in JS made every proof fail. The matrix
below covers accept and reject cases in both languages so that class of bug
cannot return silently.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tachyon.lightclient import (
    balance_key,
    balance_slot,
    build_balance_proof,
    decode_balance,
    encode_balance,
    latest_state_root,
    verify_balance_proof,
)
from tachyon.mobile_chain import BlockAssembler

HERE = os.path.dirname(os.path.abspath(__file__))
VERIFIER = os.path.join(HERE, "verify_proof.mjs")
PASSED = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"FAILED: {name} {detail}")
    PASSED.append(name)
    print(f"  ok  {name}")


def build_chain():
    """Two assembled blocks so historical and latest roots genuinely differ."""
    asm = BlockAssembler(block_weight_threshold=1000)
    asm.credit("phone-a", 500)
    asm.credit("phone-b", 700)      # block 1: phone-a=500, phone-b=700
    asm.credit("phone-a", 1200)     # block 2: phone-a=1700
    return asm


def run_js(address: str, proof: dict, state_root_hex: str):
    """Ask the JavaScript verifier for a verdict."""
    payload = json.dumps(
        {"address": address, "state_root": state_root_hex, "proof": proof}
    )
    proc = subprocess.run(
        ["node", VERIFIER, payload], capture_output=True, text=True, timeout=60
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "reason": f"verifier crashed: {proc.stderr[:120]}", "balance": None}


def test_derivation() -> None:
    print("\n[derivation]")
    check("balance_key is readable", balance_key("phone-a") == b"balance:phone-a")
    check("slot is 32 bytes", len(balance_slot("phone-a")) == 32)
    check("slot is deterministic", balance_slot("phone-a") == balance_slot("phone-a"))
    check("different addresses give different slots", balance_slot("phone-a") != balance_slot("phone-b"))
    check("balance round-trips through u64", decode_balance(encode_balance(1700)) == 1700)
    check("encoding rejects negative balances", _raises(lambda: encode_balance(-1)))


class _raises:
    def __init__(self, fn):
        self.fn = fn

    def __bool__(self):
        try:
            self.fn()
        except Exception:
            return True
        return False


def test_python_verification() -> None:
    print("\n[python verifier]")
    asm = build_chain()
    root = latest_state_root(asm.ledger)
    assert root is not None
    check("two blocks assembled", sorted(asm.ledger.blocks) == [0, 1, 2])
    check("live SMT root equals latest header root", root == asm.ledger.state.root())

    proof = build_balance_proof(asm.ledger.state, "phone-a")
    ok, reason, bal = verify_balance_proof("phone-a", proof, root)
    check("inclusion proof verifies", ok, reason)
    check("inclusion proof yields the committed balance", bal == asm.balance_of("phone-a") == 1700, str(bal))

    ok, reason, bal = verify_balance_proof("ghost", build_balance_proof(asm.ledger.state, "ghost"), root)
    check("exclusion proof verifies", ok, reason)
    check("exclusion proof yields zero", bal == 0, str(bal))

    proof_b = build_balance_proof(asm.ledger.state, "phone-b")
    ok, reason, _ = verify_balance_proof("phone-a", proof_b, root)
    check("substituting another account's proof is rejected", not ok and "different state slot" in reason, reason)

    stale = asm.ledger.blocks[1].header.state_root
    ok, reason, _ = verify_balance_proof("phone-a", proof, stale)
    check("current proof fails against an older root", not ok, reason)

    tampered = json.loads(json.dumps(proof))
    tampered["branch"][10] = "00" * 32
    ok, reason, _ = verify_balance_proof("phone-a", tampered, root)
    check("tampered branch is rejected", not ok, reason)

    inflated = json.loads(json.dumps(proof))
    inflated["value"] = encode_balance(10**9).hex()
    ok, reason, _ = verify_balance_proof("phone-a", inflated, root)
    check("inflated value is rejected", not ok, reason)

    for data, label in (
        ("nope", "string"),
        ({}, "empty object"),
        ({"slot": "zz"}, "non-hex slot"),
        ({"slot": "00" * 31, "value": None, "branch": ["00" * 32] * 256}, "31-byte slot"),
        ({"slot": "00" * 32, "value": None, "branch": ["00" * 32] * 255}, "255-entry branch"),
    ):
        ok, _, _ = verify_balance_proof("phone-a", data, root)
        check(f"malformed proof rejected: {label}", not ok)


def test_js_agreement() -> None:
    print("\n[javascript cross-check]")
    if shutil.which("node") is None:
        print("  skip  node is not installed; cannot cross-check the JS verifier")
        return

    asm = build_chain()
    root = latest_state_root(asm.ledger)
    root_hex = root.hex()
    stale_hex = asm.ledger.blocks[1].header.state_root.hex()

    proof_a = build_balance_proof(asm.ledger.state, "phone-a")
    proof_b = build_balance_proof(asm.ledger.state, "phone-b")
    proof_ghost = build_balance_proof(asm.ledger.state, "ghost")

    tampered = json.loads(json.dumps(proof_a))
    tampered["branch"][0] = "ff" * 32
    inflated = json.loads(json.dumps(proof_a))
    inflated["value"] = encode_balance(10**9).hex()

    cases = [
        ("inclusion phone-a vs latest root", "phone-a", proof_a, root_hex),
        ("inclusion phone-b vs latest root", "phone-b", proof_b, root_hex),
        ("exclusion ghost vs latest root", "ghost", proof_ghost, root_hex),
        ("wrong account substitution", "phone-a", proof_b, root_hex),
        ("current proof vs stale root", "phone-a", proof_a, stale_hex),
        ("tampered branch", "phone-a", tampered, root_hex),
        ("inflated value", "phone-a", inflated, root_hex),
        ("exclusion proof claimed for real account", "phone-a", proof_ghost, root_hex),
    ]

    for label, address, proof, root_s in cases:
        py_ok, py_reason, py_bal = verify_balance_proof(address, proof, bytes.fromhex(root_s))
        js = run_js(address, proof, root_s)
        agree = js.get("ok") == py_ok and js.get("balance") == py_bal
        check(
            f"js agrees with python: {label}",
            agree,
            f"py=({py_ok},{py_bal}) js=({js.get('ok')},{js.get('balance')}) {js.get('reason')}",
        )


def main() -> int:
    print("=" * 60)
    print("  TACHYON LIGHT-CLIENT PROOF TESTS")
    print("=" * 60)
    test_derivation()
    test_python_verification()
    test_js_agreement()
    print("\n" + "=" * 60)
    print(f"  ALL {len(PASSED)} CHECKS PASSED")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
