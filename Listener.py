import argparse, json, hmac, hashlib, time, ssl, os, threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver
from datetime import datetime, timezone

OUTFILE = "reports.jsonl"
NONCE_FILE = "seen_nonces.jsonl"

class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True

def load_seen_nonces(path):
    s = set()
    if not os.path.exists(path):
        return s
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    n = obj.get("nonce")
                    if n:
                        s.add(n)
                except Exception:
                    # tolerate plain-line nonces too
                    ln = line.strip()
                    if ln:
                        s.add(ln)
    except Exception as e:
        print("Warning: couldn't load nonces:", e)
    return s

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = self.path
        if parsed_path != "/report":
            self.send_response(404); self.end_headers(); self.wfile.write(b"Not Found"); return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        sig = self.headers.get("X-Auth-HMAC", "")

        # Verify HMAC (timing-safe)
        expected = hmac.new(self.server.secret_bytes, body, hashlib.sha256).hexdigest()
        if not sig or not hmac.compare_digest(expected, sig):
            self.send_response(403); self.end_headers()
            self.wfile.write(b"HMAC invalid")
            print(f"[{datetime.now(timezone.utc).isoformat()}] Rejected HMAC from {self.client_address}")
            return

        # Parse JSON
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception as e:
            self.send_response(400); self.end_headers(); self.wfile.write(b"Bad JSON")
            print("Bad JSON:", e)
            return

        # Timestamp and nonce checks
        now = int(time.time())
        ts = payload.get("ts")
        nonce = payload.get("nonce")
        if ts is None or nonce is None:
            self.send_response(400); self.end_headers(); self.wfile.write(b"Missing ts or nonce"); return

        try:
            ts_int = int(ts)
        except:
            self.send_response(400); self.end_headers(); self.wfile.write(b"Invalid ts"); return

        if abs(now - ts_int) > self.server.tolerance_seconds:
            self.send_response(408); self.end_headers(); self.wfile.write(b"Stale timestamp")
            print(f"[{datetime.now(timezone.utc).isoformat()}] Rejected stale ts delta={abs(now-ts_int)}s from {self.client_address}")
            return

        # replay (nonce) check (thread-safe)
        with self.server.nonce_lock:
            if nonce in self.server.seen_nonces:
                self.send_response(409); self.end_headers(); self.wfile.write(b"Replay (nonce seen)")
                print(f"[{datetime.now(timezone.utc).isoformat()}] Replayed nonce from {self.client_address}")
                return
            # accept and persist nonce
            self.server.seen_nonces.add(nonce)
            try:
                with open(self.server.nonce_file, "a", encoding="utf-8") as nf:
                    nf.write(json.dumps({"nonce": nonce, "_received_at": datetime.now(timezone.utc).isoformat()}) + "\n")
            except Exception as e:
                print("Warning: failed to persist nonce:", e)

        # Annotate and persist report
        payload["_received_at"] = datetime.now(timezone.utc).isoformat()
        payload["_from"] = self.client_address[0]
        try:
            with open(self.server.outfile, "a", encoding="utf-8") as rf:
                rf.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except Exception as e:
            print("Warning: failed to write report:", e)

        # Print a readable summary to console
        print("\n=== REPORT RECEIVED ===")
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        print("=======================\n")

        self.send_response(200); self.end_headers(); self.wfile.write(b"OK")

    def log_message(self, format, *args):
        # suppress default access log; keep console prints above
        return

def run_server(host, port, secret, certfile, keyfile, outfile, nonce_file, tolerance):
    server = ThreadedHTTPServer((host, port), Handler)
    server.secret_bytes = secret.encode("utf-8")
    server.outfile = outfile
    server.nonce_file = nonce_file
    server.tolerance_seconds = tolerance
    server.seen_nonces = load_seen_nonces(nonce_file)
    server.nonce_lock = threading.Lock()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"[+] Listener running: https://{host}:{port}  (reports -> {outfile})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--secret", required=True, help="Shared HMAC secret")
    p.add_argument("--cert", required=True, help="Server cert (cert.pem)")
    p.add_argument("--key", required=True, help="Server key (key.pem)")
    p.add_argument("--outfile", default=OUTFILE)
    p.add_argument("--nonce-file", default=NONCE_FILE)
    p.add_argument("--tolerance", type=int, default=60, help="Seconds tolerance for timestamp")
    args = p.parse_args()

    run_server(args.host, args.port, args.secret, args.cert, args.key, args.outfile, args.nonce_file, args.tolerance)
