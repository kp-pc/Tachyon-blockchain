import sys, os, time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from tachyon.simulation import run_enhanced_simulation

def ascii_bar(val, max_val, width=40):
    if max_val == 0: return "|"
    bars = int((val / max_val) * width)
    return "█" * bars + " " * (width - bars) + "|"

def run_benchmark():
    print("="*60)
    print("  TACHYON PERFORMANCE BENCHMARK (Throughput vs Scalability)")
    print("="*60)
    
    results = []
    validator_counts = [2, 4, 8, 16]
    
    for v_count in validator_counts:
        print(f"Benchmarking {v_count} validators...", end="", flush=True)
        res = run_enhanced_simulation(duration_blocks=10, num_validators=v_count)
        results.append((v_count, res['tps']))
        print(" Done.")

    max_tps = max(r[1] for r in results)
    
    print("\nTransactions Per Second (TPS) by Validator Count:")
    print("-" * 60)
    for v, tps in results:
        bar = ascii_bar(tps, max_tps)
        print(f"{v:2} Validators: {tps:8.2f} TPS {bar}")
    print("-" * 60)
    
    print("\n[Analysis] Throughput usually decreases slightly as validator count increases")
    print("due to BFT quorum complexity (N^2 communication simulated). Tachyon maintains")
    print("high performance via Ed25519 precomputation and efficient SMT batching.")

if __name__ == "__main__":
    run_benchmark()
