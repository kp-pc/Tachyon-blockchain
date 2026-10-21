"""Command-line interface for Tachyon blockchain."""

from __future__ import annotations

import argparse
import json
import socket
import sys
from typing import Any, Dict, Optional


class BlockchainClient:
    def __init__(self, rpc_host: str = "127.0.0.1", rpc_port: int = 8545):
        self.rpc_host = rpc_host
        self.rpc_port = rpc_port

    def _rpc_call(self, method: str, **params: Any) -> Any:
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((self.rpc_host, self.rpc_port))
            s.sendall(json.dumps(request).encode("utf-8"))
            response = s.recv(65536).decode("utf-8")
            s.close()
            result = json.loads(response)
            if "error" in result:
                print(f"Error: {result['error']}", file=sys.stderr)
                return None
            return result.get("result")
        except Exception as e:
            print(f"RPC connection error: {e}", file=sys.stderr)
            return None

    def get_slot(self) -> None:
        slot = self._rpc_call("getSlot")
        if slot is not None:
            print(f"Current slot: {slot}")

    def get_block(self, slot: int) -> None:
        block = self._rpc_call("getBlock", slot=slot)
        if block:
            print(json.dumps(block, indent=2))
        else:
            print(f"Block at slot {slot} not found")

    def get_finalized_slot(self) -> None:
        slot = self._rpc_call("getFinalizedSlot")
        if slot is not None:
            print(f"Finalized slot: {slot}")

    def get_balance(self, address: str) -> None:
        balance = self._rpc_call("getBalance", address=address)
        if balance is not None:
            print(f"Balance: {balance}")

    def get_hash(self) -> None:
        h = self._rpc_call("getLatestBlockHash")
        if h:
            print(f"Latest block hash: {h}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Tachyon Blockchain CLI")
    parser.add_argument("--rpc-host", default="127.0.0.1", help="RPC server host")
    parser.add_argument("--rpc-port", default=8545, type=int, help="RPC server port")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    subparsers.add_parser("slot", help="Get current slot")
    subparsers.add_parser("finalized", help="Get finalized slot")
    subparsers.add_parser("hash", help="Get latest block hash")

    block_parser = subparsers.add_parser("block", help="Get block by slot")
    block_parser.add_argument("slot", type=int, help="Slot number")

    balance_parser = subparsers.add_parser("balance", help="Get balance for address")
    balance_parser.add_argument("address", type=str, help="Wallet address")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    client = BlockchainClient(args.rpc_host, args.rpc_port)

    if args.command == "slot":
        client.get_slot()
    elif args.command == "block":
        client.get_block(args.slot)
    elif args.command == "finalized":
        client.get_finalized_slot()
    elif args.command == "balance":
        client.get_balance(args.address)
    elif args.command == "hash":
        client.get_hash()


if __name__ == "__main__":
    main()
