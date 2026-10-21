"""P2P networking for block/vote gossip among validators."""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set, Tuple

from .chain import Block, BlockHeader, Transaction, Vote, Ledger
from .encoding import canonical_json


@dataclass
class PeerInfo:
    address: str  # "host:port"
    last_seen: float
    blocks_sent: int = 0
    votes_sent: int = 0


class GossipProtocol:
    """Simple gossip protocol for propagating blocks and votes."""

    def __init__(self, ledger: Ledger, listen_port: int = 8000):
        self.ledger = ledger
        self.listen_port = listen_port
        self.peers: Dict[str, PeerInfo] = {}
        self._known_hashes: Set[str] = set()
        self._lock = threading.Lock()
        self._running = False
        self._server: Optional[socket.socket] = None

    def start(self) -> None:
        self._running = True
        try:
            self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server.bind(("0.0.0.0", self.listen_port))
            self._server.listen(5)
            self._server.settimeout(1.0)
            thread = threading.Thread(target=self._accept_loop, daemon=True)
            thread.start()
        except OSError:
            pass  # Allow running without network

    def stop(self) -> None:
        self._running = False
        if self._server:
            self._server.close()

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._server.accept()
                t = threading.Thread(target=self._handle_peer, args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                pass

    def _handle_peer(self, conn: socket.socket) -> None:
        try:
            data = conn.recv(65536).decode("utf-8")
            msg = json.loads(data)
            if msg.get("type") == "block":
                self._receive_block(msg["data"])
            elif msg.get("type") == "vote":
                self._receive_vote(msg["data"])
        except Exception:
            pass
        finally:
            conn.close()

    def _receive_block(self, data: dict) -> None:
        block_hash = data.get("hash", "")
        if block_hash in self._known_hashes:
            return
        self._known_hashes.add(block_hash)

    def _receive_vote(self, data: dict) -> None:
        pass

    def broadcast_block(self, block: Block) -> None:
        payload = {
            "type": "block",
            "data": {
                "hash": block.header.hash().hex(),
                "slot": block.header.slot,
                "leader": block.header.leader,
            },
        }
        self._broadcast(payload)

    def broadcast_vote(self, vote: Vote) -> None:
        payload = {
            "type": "vote",
            "data": {
                "voter": vote.voter,
                "slot": vote.slot,
                "block_hash": vote.block_hash.hex(),
            },
        }
        self._broadcast(payload)

    def _broadcast(self, payload: dict) -> None:
        msg = json.dumps(payload).encode("utf-8")
        with self._lock:
            for peer_key in list(self.peers.keys()):
                try:
                    host, port_str = peer_key.split(":")
                    port = int(port_str)
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2.0)
                    s.connect((host, port))
                    s.send(msg)
                    s.close()
                except Exception:
                    del self.peers[peer_key]

    def add_peer(self, host: str, port: int) -> None:
        key = f"{host}:{port}"
        with self._lock:
            if key not in self.peers:
                self.peers[key] = PeerInfo(address=key, last_seen=time.time())

    def remove_peer(self, host: str, port: int) -> None:
        key = f"{host}:{port}"
        with self._lock:
            self.peers.pop(key, None)
