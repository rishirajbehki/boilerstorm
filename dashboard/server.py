#!/usr/bin/env python3
"""Local, read-only view of the five existing host monitors."""

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from time import time


HOSTS = ("cai-fw01", "CAI-DC01", "CAI-WEB01", "cai-db01", "cai-mail01")
MAX_BODY = 16384


def parse_report(body):
    services, alerts = {}, []
    for line in body.decode("utf-8").splitlines():
        fields = line.split("\t")
        if fields[0] == "service" and len(fields) == 3:
            name, state = fields[1:]
            if not name or len(name) > 80 or state not in ("active", "inactive", "failed", "unknown"):
                raise ValueError("invalid service")
            services[name] = state
        elif fields[0] == "alert" and len(fields) == 4:
            stamp, kind, detail = fields[1:]
            if max(map(len, (stamp, kind, detail))) > 240:
                raise ValueError("invalid alert")
            alerts.append({"time": stamp, "kind": kind, "detail": detail})
        else:
            raise ValueError("invalid report line")
    if len(services) > 40 or len(alerts) > 20 or not services:
        raise ValueError("invalid report size")
    return {"services": services, "alerts": alerts}


def make_handler(state_dir, bind):
    keys = json.loads((state_dir / "keys.json").read_text(encoding="utf-8"))
    addresses = json.loads((state_dir / "addresses.json").read_text(encoding="utf-8"))
    state_file = state_dir / "status.json"
    status = json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else {}
    index = (Path(__file__).parent / "index.html").read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def respond(self, code, body=b"", content_type="text/plain; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.client_address[0] not in (bind, "127.0.0.1", "::1"):
                self.respond(403)
                return
            if self.path == "/":
                self.respond(200, index, "text/html; charset=utf-8")
            elif self.path == "/api/status":
                data = {host: status.get(host) for host in HOSTS}
                self.respond(200, json.dumps(data).encode(), "application/json; charset=utf-8")
            else:
                self.respond(404)

        def do_POST(self):
            host = self.headers.get("X-Host", "")
            stamp = self.headers.get("X-Time", "")
            signature = self.headers.get("X-Signature", "")
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if self.path != "/ingest" or host not in HOSTS or not 1 <= length <= MAX_BODY:
                    raise ValueError("request")
                if bind != "127.0.0.1" and self.client_address[0] != addresses[host]:
                    raise ValueError("source")
                if not stamp.isascii() or not stamp.isdecimal() or abs(time() - int(stamp)) > 300:
                    raise ValueError("time")
                if int(stamp) <= status.get(host, {}).get("stamp", 0):
                    raise ValueError("replay")
                body = self.rfile.read(length)
                expected = hmac.new(keys[host].encode(), stamp.encode() + b"\n" + body, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(signature, expected):
                    raise ValueError("signature")
                report = parse_report(body)
            except (ValueError, KeyError, UnicodeError):
                self.respond(400, b"Rejected report")
                return
            report.update(stamp=int(stamp), seen=int(time()))
            status[host] = report
            temp = state_file.with_suffix(".tmp")
            temp.write_text(json.dumps(status), encoding="utf-8")
            os.replace(temp, state_file)
            self.respond(204)

        def log_message(self, format, *args):
            if args and str(args[1]) != "204":
                super().log_message(format, *args)

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("init", "serve"))
    parser.add_argument("--state", type=Path, default=Path.home() / ".boilerstorm-dashboard")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    args.state.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.state, 0o700)
    keyfile = args.state / "keys.json"
    if args.action == "init":
        if keyfile.exists():
            parser.error(f"Refusing to replace existing keys: {keyfile}")
        addresses = {}
        for host in HOSTS:
            value = input(f"{host} LAN IP: ").strip()
            try:
                address = ipaddress.ip_address(value)
                if address.version != 4 or not address.is_private or address.is_loopback or value in addresses.values():
                    raise ValueError
            except ValueError:
                parser.error(f"Expected a distinct private IPv4 address for {host}")
            addresses[host] = value
        keys = {host: secrets.token_urlsafe(16) for host in HOSTS}
        (args.state / "addresses.json").write_text(json.dumps(addresses, indent=2), encoding="utf-8")
        keyfile.write_text(json.dumps(keys, indent=2), encoding="utf-8")
        os.chmod(keyfile, 0o600)
        print(f"Keep this file on cai-db01 only: {keyfile}")
        for host, key in keys.items():
            print(f"{host}: {key}")
        return
    if not keyfile.exists():
        parser.error("Run init first")
    addresses = json.loads((args.state / "addresses.json").read_text(encoding="utf-8"))
    if args.bind not in ("127.0.0.1", addresses["cai-db01"]):
        parser.error("Bind only to loopback or the cai-db01 LAN address")
    server = HTTPServer((args.bind, args.port), make_handler(args.state, args.bind))
    print(f"Dashboard: http://{args.bind}:{args.port}/ (view from cai-db01 only)", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
