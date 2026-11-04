"""P2P networking for block/vote gossip among validators."""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set, Tuple

from .chain import Block, BlockHeader, Transaction, Vote, Ledger
from .encoding import canonical_json
from .crypto import verify as crypto_verify


# ---------------------------------------------------------------------------
# Address validation helpers
# ---------------------------------------------------------------------------

def _is_valid_host(host: str) -> bool:
    """Return True for a valid IP literal or DNS hostname (no special chars)."""
    if not isinstance(host, str) or not host or len(host) > 255:
        return False
    # Try as IP address first
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # DNS hostname: letters, digits, hyphens, dots
    if host.startswith("-") or host.endswith("-") or host.startswith(".") or host.endswith("."):
        return False
    if ".." in host:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")
    return all(c in allowed for c in host)


def _is_valid_port(port: int) -> bool:
    """Port must be an integer in range 1-65535."""
    return isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535


# ---------------------------------------------------------------------------
# Peer info
# ---------------------------------------------------------------------------

@dataclass
class PeerInfo:
    address: str  # "host:port"
    last_seen: float
    blocks_sent: int = 0
    votes_sent: int = 0


# ---------------------------------------------------------------------------
# Gossip protocol
# ---------------------------------------------------------------------------

class GossipProtocol:
    """Simple gossip protocol for propagating blocks and votes."""

    def __init__(
        self,
        ledger: Ledger,
        listen_port: int = 8000,
        use_tls: bool = False,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
    ):
        self.ledger = ledger
        self.listen_port = listen_port
        self.use_tls = use_tls
        self.cert_file = cert_file
        self.key_file = key_file
        self.peers: Dict[str, PeerInfo] = {}
        # peer_key -> expected public key (32 bytes), empty = unauthenticated
        self._peer_keys: Dict[str, bytes] = {}
        self._known_hashes: Set[str] = set()
        self._lock = threading.Lock()
        self._running = False
        self._server: Optional[socket.socket] = None
        self._ssl_ctx: Optional[ssl.SSLContext] = None

        if self.use_tls:
            if not cert_file or not key_file:
                raise ValueError("TLS requires both cert_file and key_file")
            self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            self._ssl_ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)

    # ------------------------------------------------------------------
    # Peer authentication
    # ------------------------------------------------------------------

    def add_authenticated_peer(self, host: str, port: int, public_key: bytes) -> None:
        """Register a peer with its expected Ed25519 public key.

        Messages from this peer will only be processed when they carry a
        valid signature over the message body.
        """
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise ValueError("public_key must be 32 bytes")
        if not _is_valid_host(host):
            raise ValueError("invalid host")
        if not _is_valid_port(port):
            raise ValueError("invalid port")
        key = f"{host}:{port}"
        with self._lock:
            self._peer_keys[key] = public_key
            if key not in self.peers:
                self.peers[key] = PeerInfo(address=key, last_seen=time.time())

    def remove_authenticated_peer(self, host: str, port: int) -> None:
        """Remove an authenticated peer's key."""
        key = f"{host}:{port}"
        with self._lock:
            self._peer_keys.pop(key, None)

    def _verify_peer_signature(self, peer_key: str, data: dict, signature: Optional[bytes]) -> bool:
        """If the peer is authenticated, require a valid signature."""
        expected_pk = self._peer_keys.get(peer_key)
        if expected_pk is None:
            return True  # not authenticated, allow
        if not signature:
            return False
        message = canonical_json(data).encode("utf-8")
        return crypto_verify(expected_pk, message, signature)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._running = True
        try:
            self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server.bind(("[IP_ADDRESS]", self.listen_port))
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

    # ------------------------------------------------------------------
    # Accept loop
    # ------------------------------------------------------------------

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._server.accept()
                if self._ssl_ctx is not None:
                    try:
                        conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
                    except ssl.SSLError:
                        conn.close()
                        continue
                t = threading.Thread(target=self._handle_peer, args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Peer message handling
    # ------------------------------------------------------------------

    def _handle_peer(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5.0)
            data = conn.recv(65536).decode("utf-8")
            msg = json.loads(data)

            # Determine sender identity from the connection
            peer_addr = conn.getpeername()
            peer_host = peer_addr[0] if peer_addr else "unknown"
            peer_key = f"{peer_host}:{peer_addr[1] if peer_addr else 0}"

            msg_type = msg.get("type")
            payload = msg.get("data", {})
            signature = msg.get("signature")
            if isinstance(signature, str):
                try:
                    signature = bytes.fromhex(signature)
                except ValueError:
                    signature = None

            # Verify peer signature if authenticated
            if not self._verify_peer_signature(peer_key, payload, signature):
                return

            if msg_type == "block":
                self._receive_block(payload)
            elif msg_type == "vote":
                self._receive_vote(payload)
        except Exception:
            pass
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Block validation
    # ------------------------------------------------------------------

    def _receive_block(self, data: dict) -> None:
        block_hash = data.get("hash", "")
        if block_hash in self._known_hashes:
            return

        # --- Validate block header ---
        try:
            header = BlockHeader(
                slot=data["slot"],
                parent_slot=data["parent_slot"],
                parent_hash=bytes.fromhex(data["parent_hash"]),
                transactions_root=bytes.fromhex(data["transactions_root"]),
                state_root=bytes.fromhex(data["state_root"]),
                base_fee=data.get("base_fee", 0),
                leader=data["leader"],
                timestamp=data["timestamp"],
            )
        except (KeyError, ValueError):
            return

        # 1. Block hash must match the header
        expected_hash = header.hash().hex()
        if block_hash != expected_hash:
            return

        # 2. Parent hash must link to a known block (or genesis)
        if header.parent_slot != -1:
            parent = self.ledger.blocks.get(header.parent_slot)
            if parent is None:
                return
            if parent.header.hash() != header.parent_hash:
                return
        else:
            # Genesis: parent_hash must be zero
            if header.parent_hash != bytes(32):
                return

        # 3. If a signature is provided, verify it against the leader's key
        sig_hex = data.get("signature")
        if sig_hex:
            try:
                signature = bytes.fromhex(sig_hex)
                message = canonical_json({
                    "slot": header.slot,
                    "parent_slot": header.parent_slot,
                    "parent_hash": header.parent_hash.hex(),
                    "transactions_root": header.transactions_root.hex(),
                    "state_root": header.state_root.hex(),
                    "base_fee": header.base_fee,
                    "leader": header.leader,
                    "timestamp": header.timestamp,
                }).encode("utf-8")
                from .crypto import public_key_from_address
                leader_pk = public_key_from_address(header.leader)
                if not crypto_verify(leader_pk, message, signature):
                    return
            except Exception:
                return

        self._known_hashes.add(block_hash)

    def _receive_vote(self, data: dict) -> None:
        pass

    # ------------------------------------------------------------------
    # Broadcasting
    # ------------------------------------------------------------------

    def broadcast_block(self, block: Block) -> None:
        payload = {
            "type": "block",
            "data": {
                "hash": block.header.hash().hex(),
                "slot": block.header.slot,
                "leader": block.header.leader,
                "parent_slot": block.header.parent_slot,
                "parent_hash": block.header.parent_hash.hex(),
                "transactions_root": block.header.transactions_root.hex(),
                "state_root": block.header.state_root.hex(),
                "base_fee": block.header.base_fee,
                "timestamp": block.header.timestamp,
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
                    if self.use_tls and self._ssl_ctx is not None:
                        # Client-side TLS: create a new context per connection
                        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        s = ctx.wrap_socket(s)
                    s.settimeout(2.0)
                    s.connect((host, port))
                    s.send(msg)
                    s.close()
                except Exception:
                    del self.peers[peer_key]

    # ------------------------------------------------------------------
    # Peer management (with validation)
    # ------------------------------------------------------------------

    def add_peer(self, host: str, port: int) -> None:
        """Add a peer after validating host and port."""
        if not _is_valid_host(host):
            raise ValueError(f"invalid host: {host!r}")
        if not _is_valid_port(port):
            raise ValueError(f"invalid port: {port!r}")
        key = f"{host}:{port}"
        with self._lock:
            if key not in self.peers:
                self.peers[key] = PeerInfo(address=key, last_seen=time.time())

    def remove_peer(self, host: str, port: int) -> None:
        key = f"{host}:{port}"
        with self._lock:
            self.peers.pop(key, None)
