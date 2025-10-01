import argparse, platform, socket, json, hmac, hashlib, time, uuid, sys
from datetime import datetime
from urllib import request, error
import ssl

def list_local_ips():
    ips = []
    try:
        for res in socket.getaddrinfo(socket.gethostname(), None):
            if res[0] == socket.AF_INET:
                ips.append(res[4][0])
    except:
        ips.append("127.0.0.1")
    return list(dict.fromkeys(ips))  # preserve order, dedupe

def build_report(agent_name):
    return {
        "agent_name": agent_name,
        "hostname": socket.gethostname(),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
        },
        "local_ips": list_local_ips(),
        "time_iso": datetime.utcnow().isoformat() + "Z",
        "nonce": uuid.uuid4().hex,
        "ts": int(time.time()),
    }

def post_json(url, secret, data, cafile=None, timeout=6):
    # canonical JSON (no extra spaces) so HMAC is computed on the exact bytes sent
    body = json.dumps(data, separators=(",", ":"), sort_keys=False).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    headers = {"Content-Type": "application/json", "X-Auth-HMAC": sig}
    req = request.Request(url, data=body, headers=headers, method="POST")

    if cafile:
        ctx = ssl.create_default_context(cafile=cafile)
    else:
        ctx = ssl.create_default_context()
    opener = request.build_opener(request.HTTPSHandler(context=ctx))

    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read().decode("utf-8", errors="ignore")
    except error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return None, str(e)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--collector", required=True, help="host:port of listener")
    p.add_argument("--secret", required=True, help="shared HMAC secret")
    p.add_argument("--name", default=None, help="agent name")
    p.add_argument("--cafile", default=None, help="CA cert to verify listener (lab-ca.crt)")
    args = p.parse_args()

    host, port = args.collector.split(":")
    url = f"https://{host}:{port}/report"
    report = build_report(args.name or socket.gethostname())
    code, text = post_json(url, args.secret, report, cafile=args.cafile)
    if code != 200:
        # output only on failure so the app is silent on success
        sys.stderr.write(f"Send failed: {code} {text}\n")
        sys.exit(2)
    sys.exit(0)

if __name__ == "__main__":
    main()
