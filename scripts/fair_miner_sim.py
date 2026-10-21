import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from tachyon.pow import simulate_fair_mining

if __name__ == "__main__":
    simulate_fair_mining(b"tachyon_genesis", rounds=3)
