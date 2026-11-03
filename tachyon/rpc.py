"""JSON-RPC API for Tachyon blockchain."""

from __future__ import annotations

import json
import os
import secrets
import socket
import threading
import time
import ipaddress
from typing import Any, Callable, Dict, Optional

from .chain import Ledger, BlockHeader, Block, Transaction, Vote, BASE_FEE_INITIAL
from .lightclient import balance_key, proof_to_dict, latest_state_root

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_BODY_SIZE = 64 * 1024  # 64 KB
RATE_LIMIT_MAX = 100
RATE_LIMIT_WINDOW = 10.0  # seconds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ADDRESS_RE_CACHE: Optional["re.Pattern[str]"] = None


def _address_pattern() -> "re.Pattern[str]":
    """Lazily compile the address regex (imported from crypto module)."""
    global _ADDRESS_RE_CACHE
    if _ADDRESS_RE_CACHE is None:
        import re
        from .crypto import ADDRESS_PREFIX
        # Tachyon addresses look like: tch + base58ish payload + 4-byte checksum
        _ADDRESS_RE_CACHE = re.compile(
            r"^" + re.escape(ADDRESS_PREFIX) + r"[1-9A-HJ-NP-Za-km-z]{25,40}$"
        )
    return _ADDRESS_RE_CACHE


def _is_valid_address(address: str) -> bool:
    """Check structural address format and try a checksum decode."""
    if not isinstance(address, str) or not address:
        return False
    if not _address_pattern().match(address):
        return False
    try:
        from .crypto import public_key_from_address
        public_key_from_address(address)
        return True
    except Exception:
        return False


def _is_valid_slot(slot: Any) -> bool:
    """Slot must be a non-negative integer (not bool)."""
    return isinstance(slot, int) and not isinstance(slot, bool) and slot >= 0


def _is_valid_ip(host: str) -> bool:
    """Return True when host is a valid IPv4/IPv6 literal or a DNS hostname."""
    if not isinstance(host, str) or not host or len(host) > 255:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # DNS hostname: letters, digits, hyphens, dots; no leading/trailing dot/hyphen
    if host.startswith("-") or host.endswith("-") or host.startswith(".") or host.endswith("."):
        return False
    if ".." in host:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")
    return all(c in allowed for c in host)


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Simple per-IP fixed-window rate limiter with lazy cleanup."""

    def __init__(self, max_requests: int, window_seconds: float):
        self._max = max_requests
        self._window = window_seconds
        self._hits: Dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            stamps = self._hits.get(ip)
            if stamps is None:
                self._hits[ip] = [now]
                return True
            # Drop expired entries
            cutoff = now - self._window
            recent = [t for t in stamps if t > cutoff]
            if len(recent) >= self._max:
                self._hits[ip] = recent
                return False
            recent.append(now)
            self._hits[ip] = recent
            return True

    def _cleanup(self) -> None:
        """Remove IPs that have no recent hits."""
        now = time.time()
        cutoff = now - self._window
        with self._lock:
            empty = [ip for ip, stamps in self._hits.items()
                     if not stamps or stamps[-1] <= cutoff]
            for ip in empty:
                del self._hits[ip]


# ---------------------------------------------------------------------------
# RPC server
# ---------------------------------------------------------------------------

class JsonRpcServer:
    """JSON-RPC server for blockchain queries with auth and rate limiting."""

    def __init__(
        self,
        ledger: Ledger,
        host: str = "[IP_ADDRESS]",
        port: int = 8545,
        api_key: Optional[str] = None,
    ):
        self.ledger = ledger
        self.host = host
        self.port = port
        # API key: explicit arg > env var > auto-generated
        self._api_key = (
            api_key
            or os.environ.get("TACHYON_RPC_API_KEY")
            or secrets.token_hex(32)
        )
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
        self._rate_limiter = _RateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW)
        self._last_cleanup = time.time()

    @property
    def api_key(self) -> str:
        """Expose the active API key for clients/tests."""
        return self._api_key

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

    # ------------------------------------------------------------------
    # Connection handling
    # ------------------------------------------------------------------

    def _handle_connection(self, conn: socket.socket) -> None:
        client_ip = conn.getpeername()[0] if conn.getpeername() else "unknown"
        try:
            conn.settimeout(5.0)
            # --- body size limit ---
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_BODY_SIZE:
                    self._send_error(conn, 413, "Request body too large")
                    return
                chunks.append(chunk)
                # Heuristic: stop when we have what looks like a complete JSON
                try:
                    json.loads(b"".join(chunks))
                    break
                except json.JSONDecodeError:
                    continue

            raw = b"".join(chunks)
            try:
                request = json.loads(raw)
            except json.JSONDecodeError:
                self._send_error(conn, 400, "Invalid JSON")
                return

            # --- rate limiting ---
            if not self._rate_limiter.allow(client_ip):
                self._send_error(conn, 429, "Too many requests")
                return

            # --- API key auth ---
            if not self._check_api_key(request):
                self._send_error(conn, 401, "Unauthorized: invalid or missing API key")
                return

            response = self._process_request(request)
            conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
        except Exception as e:
            try:
                self._send_error(conn, 500, str(e))
            except Exception:
                pass
        finally:
            conn.close()
            # Lazy cleanup every 30 seconds
            now = time.time()
            if now - self._last_cleanup > 30:
                self._rate_limiter._cleanup()
                self._last_cleanup = now

    def _send_error(self, conn: socket.socket, code: int, message: str) -> None:
        body = json.dumps({
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": None,
        })
        conn.sendall(body.encode("utf-8"))

    # ------------------------------------------------------------------
    # Auth / rate-limit helpers
    # ------------------------------------------------------------------

    def _check_api_key(self, request: dict) -> bool:
        """Accept the key in the top-level ``apiKey`` field or the
        ``X-Api-Key`` HTTP-style header inside the JSON envelope."""
        provided = request.get("apiKey") or request.get("api_key") or request.get("X-Api-Key")
        if not isinstance(provided, str) or not provided:
            return False
        return secrets.compare_digest(provided, self._api_key)

    # ------------------------------------------------------------------
    # Request dispatch
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # RPC handlers (with validation)
    # ------------------------------------------------------------------

    def get_slot(self) -> int:
        return self.ledger.current_slot

    def get_block(self, slot: int) -> Optional[dict]:
        if not _is_valid_slot(slot):
            raise ValueError("slot must be a non-negative integer")
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
        if not _is_valid_address(address):
            raise ValueError("address must be a valid non-empty Tachyon address")
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
        if not _is_valid_address(address):
            raise ValueError("address must be a valid non-empty Tachyon address")
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
