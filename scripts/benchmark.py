import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tachyon.simulation import simulation


def bar(value: float, peak: float, width: int = 36) -> str:
    filled = 0 if peak <= 0 else int((value / peak) * width)
    return "#" * filled + " " * (width - filled) + "|"


def main() -> None:
    print("=" * 62)
    print("  TACHYON PERFORMANCE BENCHMARK (Throughput vs Validator Count)")
    print("=" * 62)
    rows = []
    for count in (2, 4, 8, 16):
        res = simulation(duration_blocks=10, num_validators=count, fair_play_rounds=1)
        if not res["chain_integrity_ok"]:
            print(f"  {count:>2} validators: FAILED {res['errors']}")
            continue
        rows.append((count, res["performance"]["txs_per_sec"]))
        print(f"  benchmarked {count} validators -> {res['performance']['txs_per_sec']} tx/s")

    if not rows:
        print("No successful benchmark runs")
        return

    peak = max(tps for _, tps in rows)
    print("\nTransactions Per Second (tx/s) by Validator Count")
    print("-" * 62)
    for count, tps in rows:
        print(f"{count:>2} Validators: {tps:8.2f} tx/s {bar(tps, peak)}")
    print("-" * 62)
    print("Note: throughput includes Ed25519 signing/verification and SMT updates.")


if __name__ == "__main__":
    main()
