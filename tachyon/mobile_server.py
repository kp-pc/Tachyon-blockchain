"""HTTP transport so an Android phone can reach a Tachyon mining pool.

Why HTTP instead of a custom socket protocol
--------------------------------------------
A phone on mobile data sits behind carrier NAT: it cannot accept inbound
connections and its long-lived TCP sessions get dropped when the radio sleeps.
Short HTTP request/response pairs survive NAT rebinding, traverse any proxy, and
are the lowest-friction thing to call from a browser (plain ``fetch``) or from
Termux (``curl``).

Security posture
----------------
This is a *share submission* service, not a wallet. The only protected asset is
share credit, and the HMAC-signed ticket already stops difficulty forgery. The
client holds no private key, so a compromised phone cannot steal funds -- it can
only submit work. For real deployment you must add TLS, per-IP rate limiting and
reverse-proxy timeouts; see ``DEPLOYMENT_NOTES`` at the bottom of this module.

Endpoints (JSON in, JSON out)
-----------------------------
POST /register   {miner, tier}                        -> {ok, miner, tier, difficulty}
POST /ticket     {miner, tier, hashes_per_second?}    -> {ok, ticket}
POST /share      {ticket, nonce, elapsed_ms?}         -> {ok, credited, reason, weight}
GET  /status                                          -> pool status
GET  /leaderboard                                     -> ranked miners
GET  /health                                          -> {ok, version}
GET  /                                                -> embedded mining page
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional, Tuple

from .mobile_pool import MobilePool

MAX_BODY_BYTES = 64 * 1024

DEPLOYMENT_NOTES = """
Before exposing this beyond localhost/lan you MUST:
  1. Terminate TLS in front of it (Caddy/nginx). Plain HTTP leaks tickets to the
     network, and a leaked ticket lets an observer race the submit.
  2. Add per-IP rate limiting on /ticket and /share, otherwise one client can
     drain the pool's CPU by requesting tickets in a loop.
  3. Persist consumed ticket ids, or a restart makes old tickets replayable
     within their TTL window.
  4. Set a real BLOCK_WEIGHT_THRESHOLD; the default is sized for demos.
"""


class _Router:
    """Tiny exact-path router. Keeps the handler method free of if-chains."""

    def __init__(self):
        self.routes: Dict[Tuple[str, str], Callable[[dict], Any]] = {}
        self.gets: Dict[str, Callable[[], Any]] = {}

    def post(self, path: str):
        def register(fn):
            self.routes[("POST", path)] = fn
            return fn

        return register

    def get(self, path: str, raw: bool = False):
        def register(fn):
            self.gets[path] = fn
            return fn

        return register


class MiningServer:
    """Wraps a MobilePool in an HTTP server for phone clients."""

    def __init__(self, pool: Optional[MobilePool] = None, host: str = "0.0.0.0", port: int = 8080):
        self.pool = pool or MobilePool()
        self.host = host
        self.port = port
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    # ---------- endpoint implementations ----------

    def _register(self, body: dict) -> dict:
        miner = body.get("miner")
        if not miner or not isinstance(miner, str):
            raise ValueError("miner is required")
        tier = int(body.get("tier", 1))
        if tier not in (1, 2, 4, 8):
            raise ValueError("tier must be one of 1, 2, 4, 8")
        account = self.pool.register(miner, tier)
        return {"ok": True, "miner": account.address, "tier": account.tier, "difficulty": account.difficulty}

    def _ticket(self, body: dict) -> dict:
        miner = body.get("miner")
        if not miner or not isinstance(miner, str):
            raise ValueError("miner is required")
        tier = int(body.get("tier", 1))
        hashes_per_second = body.get("hashes_per_second")
        if hashes_per_second is not None:
            hashes_per_second = float(hashes_per_second)
            if not hashes_per_second > 0:
                raise ValueError("hashes_per_second must be positive")
        ticket = self.pool.request_ticket(miner, tier, hashes_per_second=hashes_per_second)
        return {"ok": True, "ticket": ticket.to_dict()}

    def _share(self, body: dict) -> dict:
        ticket = body.get("ticket")
        if not isinstance(ticket, dict):
            raise ValueError("ticket object is required")
        nonce = body.get("nonce")
        try:
            nonce = int(nonce)
        except (TypeError, ValueError):
            raise ValueError("nonce must be an integer")
        elapsed_ms = body.get("elapsed_ms")
        if elapsed_ms is not None:
            try:
                elapsed_ms = int(elapsed_ms)
            except (TypeError, ValueError):
                elapsed_ms = None
        record = self.pool.submit_share(ticket, nonce, elapsed_ms=elapsed_ms)
        return {
            "ok": record.credited,
            "credited": record.credited,
            "reason": record.reason,
            "weight": record.weight,
            "difficulty": record.difficulty,
        }

    # ---------- server plumbing ----------

    def _make_handler(self):
        server = self
        router = _Router()
        router.post("/register")(server._register)
        router.post("/ticket")(server._ticket)
        router.post("/share")(server._share)

        class Handler(BaseHTTPRequestHandler):
            server_version = "TachyonMining/0.1"

            def log_message(self, fmt, *args):  # keep test output readable
                return

            def _send(self, code: int, payload: Any, content_type: str = "application/json"):
                if isinstance(payload, (dict, list)):
                    body = json.dumps(payload).encode()
                elif isinstance(payload, str):
                    body = payload.encode()
                else:
                    body = payload
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_OPTIONS(self):
                self.send_response(204)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.end_headers()

            def do_GET(self):
                path = self.path.split("?", 1)[0]
                if path == "/health":
                    return self._send(200, {"ok": True, "version": "0.1.0"})
                if path == "/status":
                    return self._send(200, {"ok": True, **server.pool.status()})
                if path == "/leaderboard":
                    return self._send(200, {"ok": True, "miners": server.pool.leaderboard()})
                if path in ("/", "/index.html"):
                    return self._send(200, CLIENT_HTML, "text/html; charset=utf-8")
                return self._send(404, {"ok": False, "error": "not found"})

            def do_POST(self):
                path = self.path.split("?", 1)[0]
                handler = router.routes.get(("POST", path))
                if handler is None:
                    return self._send(404, {"ok": False, "error": "not found"})
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    return self._send(400, {"ok": False, "error": "bad content-length"})
                if length > MAX_BODY_BYTES:
                    return self._send(413, {"ok": False, "error": "body too large"})
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    body = json.loads(raw.decode("utf-8"))
                    if not isinstance(body, dict):
                        raise ValueError("body must be a JSON object")
                except (ValueError, UnicodeDecodeError) as exc:
                    return self._send(400, {"ok": False, "error": f"bad json: {exc}"})
                try:
                    result = handler(body)
                except ValueError as exc:
                    return self._send(400, {"ok": False, "error": str(exc)})
                except Exception as exc:  # never leak a stack trace to a phone
                    return self._send(500, {"ok": False, "error": f"internal error: {type(exc).__name__}"})
                return self._send(200, result)

        return Handler

    def start(self) -> None:
        self._httpd = ThreadingHTTPServer((self.host, self.port), self._make_handler())
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def url(self) -> str:
        return f"http://{self.host}:{self.port}"


CLIENT_HTML = """<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Tachyon Mobile Miner</title>
<style>
:root{color-scheme:dark}
body{margin:0;font:16px/1.45 system-ui,-apple-system,sans-serif;background:#0b0a12;color:#e8e6f0;
     padding:20px;display:flex;flex-direction:column;gap:14px;max-width:560px;margin:0 auto}
h1{font-size:20px;margin:0;letter-spacing:.5px}
.sub{color:#8d88a8;font-size:13px}
.card{background:#16141f;border:1px solid #262238;border-radius:14px;padding:16px}
.row{display:flex;justify-content:space-between;padding:5px 0;font-size:14px}
.row b{font-variant-numeric:tabular-nums}
button{width:100%;padding:15px;border:0;border-radius:12px;font-size:16px;font-weight:600;
       background:#7c5cff;color:#fff}
button:disabled{background:#312b4d;color:#8d88a8}
.bar{height:7px;background:#262238;border-radius:99px;overflow:hidden}
.bar>i{display:block;height:100%;width:0;background:#7c5cff;transition:width .2s}
#log{font:11px/1.5 ui-monospace,monospace;color:#8d88a8;max-height:130px;overflow:auto;white-space:pre-wrap}
input{width:100%;padding:11px;border-radius:10px;border:1px solid #262238;background:#0b0a12;
      color:#e8e6f0;font-size:14px;box-sizing:border-box}
</style></head>
<body>
<h1>&#9889; Tachyon Mobile Miner</h1>
<div class="sub">Bounded work tickets &mdash; a few seconds of hashing, then rest. No battery cooking.</div>

<div class="card">
  <label class="sub">Miner name</label>
  <input id="miner" value="" placeholder="my-phone">
</div>

<div class="card">
  <div class="row"><span>Device hash rate</span><b id="hps">&mdash;</b></div>
  <div class="row"><span>Ticket difficulty</span><b id="diff">&mdash;</b></div>
  <div class="row"><span>Expected solve</span><b id="eta">&mdash;</b></div>
  <div class="row"><span>Shares accepted</span><b id="accepted">0</b></div>
  <div class="row"><span>Total credit</span><b id="credit">0</b></div>
  <div class="row"><span>Pool miners</span><b id="miners">&mdash;</b></div>
  <div class="bar" style="margin-top:10px"><i id="prog"></i></div>
</div>

<button id="go">Start mining</button>
<div class="card"><div id="log">idle</div></div>

<script>
// Compact synchronous SHA-256. WebCrypto is async-per-call and roughly 100x
// too slow to drive a hash loop, so we inline a fixed implementation. The
// server contract is: sha256(seed[32] || nonce as 8-byte big-endian).
const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function sha256bytes(bytes){
  const H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const l=bytes.length, bitLen=l*8;
  const withPad=new Uint8Array((((l+9)+63)>>6)<<6);
  withPad.set(bytes); withPad[l]=0x80;
  // 32-bit length only: our input is always < 2^29 bytes
  new DataView(withPad.buffer).setUint32(withPad.length-4, bitLen>>>0, false);
  const W=new Uint32Array(64);
  const dv=new DataView(withPad.buffer);
  const R=(x,n)=>(x>>>n)|(x<<(32-n));
  for(let off=0;off<withPad.length;off+=64){
    for(let i=0;i<16;i++) W[i]=dv.getUint32(off+i*4,false);
    for(let i=16;i<64;i++){
      const s0=R(W[i-15],7)^R(W[i-15],18)^(W[i-15]>>>3);
      const s1=R(W[i-2],17)^R(W[i-2],19)^(W[i-2]>>>10);
      W[i]=(W[i-16]+s0+W[i-7]+s1)>>>0;
    }
    let [a,b,c,d,e,f,g,h]=H;
    for(let i=0;i<64;i++){
      const S1=R(e,6)^R(e,11)^R(e,25);
      const ch=(e&f)^(~e&g);
      const t1=(h+S1+ch+K[i]+W[i])>>>0;
      const S0=R(a,2)^R(a,13)^R(a,22);
      const maj=(a&b)^(a&c)^(b&c);
      const t2=(S0+maj)>>>0;
      h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
    }
    H[0]=(H[0]+a)>>>0;H[1]=(H[1]+b)>>>0;H[2]=(H[2]+c)>>>0;H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0;H[5]=(H[5]+f)>>>0;H[6]=(H[6]+g)>>>0;H[7]=(H[7]+h)>>>0;
  }
  const out=new Uint8Array(32), dv2=new DataView(out.buffer);
  for(let i=0;i<8;i++) dv2.setUint32(i*4,H[i],false);
  return out;
}

const $=id=>document.getElementById(id);
const log=m=>{$('log').textContent=m+'\\n'+$('log').textContent.split('\\n').slice(0,12).join('\\n');};
$('miner').value='phone-'+Math.random().toString(36).slice(2,7);

let stop=false, accepted=0, credit=0;
const buf=new Uint8Array(40); // 32-byte seed + 8-byte nonce

function meetsTarget(hash, difficulty){
  // require the first (256-difficulty) bits to be zero, i.e. hash < 2^(256-diff)
  const zeroBits=difficulty;
  const fullBytes=zeroBits>>3, remBits=zeroBits&7;
  for(let i=0;i<fullBytes;i++) if(hash[i]!==0) return false;
  if(remBits===0) return true;
  return hash[fullBytes] < (1<<(8-remBits));
}

async function post(path, body){
  const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  return r.json();
}

async function loop(){
  while(!stop){
    let tk;
    try{
      const t0=performance.now();
      // calibration burst: measure real hash rate on this device
      for(let i=0;i<3000;i++){ buf[0]=i&255; sha256bytes(buf); }
      const hps = 3000/((performance.now()-t0)/1000);
      $('hps').textContent = (hps/1000).toFixed(1)+'k h/s';

      const res=await post('/ticket',{miner:$('miner').value,tier:1,hashes_per_second:hps});
      if(!res.ok){log('ticket error: '+res.error);await sleep(3000);continue;}
      tk=res.ticket;
    }catch(e){ log('network: '+e.message); await sleep(4000); continue; }

    const seed=Uint8Array.from(tk.seed.match(/../g).map(h=>parseInt(h,16)));
    buf.set(seed,0);
    $('diff').textContent=tk.difficulty;
    $('eta').textContent=(Math.pow(2,tk.difficulty)/parseFloat($('hps').textContent)*1000).toFixed(1)+'s';

    const deadline=performance.now()+Math.min(9000,(tk.expires_at_ms-Date.now()));
    let nonce=0, found=null, started=performance.now();

    while(performance.now()<deadline){
      if(stop) return;
      for(let i=0;i<600;i++){
        const dvn=new DataView(buf.buffer);
        dvn.setUint32(32,Math.floor(nonce/4294967296),false);
        dvn.setUint32(36,nonce>>>0,false);
        if(meetsTarget(sha256bytes(buf), tk.difficulty)){ found=nonce; break; }
        nonce++;
      }
      $('prog').style.width=Math.min(100,(nonce/Math.pow(2,tk.difficulty))*100)+'%';
      await sleep(0); // yield so the UI stays responsive
      if(found!==null) break;
    }
    $('prog').style.width='0%';

    if(found===null){ log('ticket expired without a share'); continue; }

    try{
      const r=await post('/share',{ticket:tk,nonce:found,elapsed_ms:Math.round(performance.now()-started)});
      if(r.credited){ accepted++; credit+=r.weight; $('accepted').textContent=accepted;
        $('credit').textContent=credit.toLocaleString(); log('share accepted, weight '+r.weight.toLocaleString()); }
      else log('share rejected: '+r.reason);
    }catch(e){ log('submit failed: '+e.message); }

    await sleep(300); // rest between tickets
  }
}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));

$('go').onclick=async()=>{
  stop=!stop;
  $('go').textContent=stop?'Stop mining':'Start mining';
  if(!stop){ log('mining started'); loop(); }
  else log('mining stopped');
};

(async()=>{
  setInterval(async()=>{
    try{ const s=await (await fetch('/status')).json(); $('miners').textContent=s.miners; }catch(e){}
  },4000);
})();
</script>
</body></html>
"""


def main(argv: Optional[list] = None) -> int:
    """CLI entry point: ``python -m tachyon.mobile_server --port 8080``."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="tachyon.mobile_server",
        description="Tachyon mobile mining pool over HTTP",
    )
    parser.add_argument("--host", default="0.0.0.0", help="bind address (default 0.0.0.0 so a phone on the LAN can reach it)")
    parser.add_argument("--port", type=int, default=8080, help="bind port (default 8080, use 0 for an ephemeral port)")
    parser.add_argument("--target-seconds", type=float, default=3.0, help="expected solve time per ticket (default 3.0)")
    parser.add_argument(
        "--block-weight",
        type=int,
        default=None,
        help="accumulated share weight that assembles one block (default: pool default)",
    )
    args = parser.parse_args(argv)

    pool = MobilePool(target_seconds=args.target_seconds)
    if args.block_weight is not None:
        if args.block_weight <= 0:
            parser.error("--block-weight must be positive")
        pool.block_weight_threshold = args.block_weight

    server = MiningServer(pool=pool, host=args.host, port=args.port)
    server.start()

    shown = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    print("Tachyon mobile mining pool")
    print(f"  listening on http://{args.host}:{server.port}")
    print(f"  open on your phone: http://<this-machine-ip>:{server.port}/")
    print(f"  target solve time : {args.target_seconds}s per ticket")
    print(f"  block threshold   : {pool.block_weight_threshold:,} share weight")
    print("  press Ctrl-C to stop", flush=True)

    try:
        while True:
            import time

            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        server.stop()
        status = pool.status()
        print(
            "final: "
            f"{status['miners']} miners, "
            f"{status['shares_accepted']} accepted, "
            f"{status['shares_rejected']} rejected, "
            f"{status['blocks_assembled']} blocks assembled"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
