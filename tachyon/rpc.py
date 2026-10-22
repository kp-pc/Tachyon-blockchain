"""JSON-RPC API for Tachyon blockchain."""

from __future__ import annotations

import json
import socket
import threading
from typing import Any, Callable, Dict, Optional

from .chain import Ledger, BlockHeader, Block, Transaction, Vote, BASE_FEE_INITIAL
from .lightclient import balance_key, proof_to_dict, latest_state_root


class JsonRpcServer:
    """Simple JSON-RPC server for blockchain queries."""

    def __init__(self, ledger: Ledger, host: str = "127.0.0.1", port: int = 8545):
        self.ledger = ledger
        self.host = host
        self.port = port
        self._handlers: Dict[str, Callable] = {
            "getSlot": self.get_slot,
            "getBlock": self.get_block,
            "getFinalizedSlot": self.get_finalized_slot,
            "getBalance": self.get_balance,
            "getLatestBlockHash": self.get_latest_block_hash,
            "getLatestBlockHeader": self.get_latest_block_header,
            "getMinerBalanceProof": self.get_miner_balance_proof,
        }
        self._server: Optional[socket.socket] = None
        self._running = False

    def start(self) -> None:
        self._running = True
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(10)
        self._server.settimeout(1.0)
        thread = threading.Thread(target=self._accept_loop, daemon=True)
        thread.start()

    def stop(self) -> None:
        self._running = False
        if self._server:
            self._server.close()

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._server.accept()
                t = threading.Thread(target=self._handle_connection, args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                pass

    def _handle_connection(self, conn: socket.socket) -> None:
        try:
            data = conn.recv(65536).decode("utf-8")
            request = json.loads(data)
            response = self._process_request(request)
            conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
        except Exception as e:
            conn.sendall((json.dumps({"error": str(e)}) + "\n").encode("utf-8"))
        finally:
            conn.close()

    def _process_request(self, request: dict) -> dict:
        method = request.get("method", "")
        params = request.get("params", {})
        req_id = request.get("id", 0)

        handler = self._handlers.get(method)
        if handler is None:
            return {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": req_id}

        try:
            result = handler(**params)
            return {"jsonrpc": "2.0", "result": result, "id": req_id}
        except Exception as e:
            return {"jsonrpc": "2.0", "error": {"code": -32000, "message": str(e)}, "id": req_id}

    def get_slot(self) -> int:
        return self.ledger.current_slot

    def get_block(self, slot: int) -> Optional[dict]:
        block = self.ledger.blocks.get(slot)
        if block is None:
            return None
        return {
            "slot": block.header.slot,
            "hash": block.header.hash().hex(),
            "parent_slot": block.header.parent_slot,
            "parent_hash": block.header.parent_hash.hex(),
            "transactions_root": block.header.transactions_root.hex(),
            "state_root": block.header.state_root.hex(),
            "leader": block.header.leader,
            "timestamp": block.header.timestamp,
            "num_transactions": len(block.transactions),
        }

    def get_finalized_slot(self) -> int:
        return self.ledger.finalized_slot

    def get_balance(self, address: str) -> int:
        return self.ledger.get_stake(address)

    def get_latest_block_header(self) -> Optional[dict]:
        """Header fields a light client needs, without the transaction bodies."""
        if not self.ledger.blocks:
            return None
        block = self.ledger.blocks[max(self.ledger.blocks)]
        return {
            "slot": block.header.slot,
            "hash": block.header.hash().hex(),
            "parent_slot": block.header.parent_slot,
            "parent_hash": block.header.parent_hash.hex(),
            "state_root": block.header.state_root.hex(),
            "transactions_root": block.header.transactions_root.hex(),
            "leader": block.header.leader,
            "timestamp": block.header.timestamp,
        }

    def get_miner_balance_proof(self, address: str) -> dict:
        """SMT inclusion proof for a miner's committed balance.

        The caller must verify the returned proof against a header's
        ``state_root``; this response alone proves nothing.
        """
        if not isinstance(address, str) or not address:
            raise ValueError("address must be a non-empty string")
        proof = proof_to_dict(self.ledger.state.prove(balance_key(address)))
        return {
            "address": address,
            "state_root": self.ledger.state.root().hex(),
            "proof": proof,
        }

    def get_latest_block_hash(self) -> str:
        if not self.ledger.blocks:
            return bytes(32).hex()
        max_slot = max(self.ledger.blocks.keys())
        block = self.ledger.blocks[max_slot]
        return block.header.hash().hex()
