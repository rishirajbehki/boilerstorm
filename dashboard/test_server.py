import hashlib
import hmac
import json
from http.server import HTTPServer
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Thread
from time import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from server import HOSTS, make_handler, parse_report


class DashboardTests(unittest.TestCase):
    def test_init_keeps_addresses_local(self):
        with TemporaryDirectory() as directory:
            inputs = "".join(f"10.1.1.{i}\n" for i in range(1, 6))
            run = subprocess.run([sys.executable, str(Path(__file__).parent / "server.py"),
                                  "init", "--state", directory], input=inputs, text=True,
                                 capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(len(json.loads((Path(directory) / "addresses.json").read_text())), 5)
            self.assertEqual(len(json.loads((Path(directory) / "keys.json").read_text())), 5)

    def test_report_validation(self):
        self.assertEqual(parse_report(b"service\tDNS\tactive\n")["services"], {"DNS": "active"})
        for body in (b"", b"service\tDNS\tstarted\n", b"alert\t1\tchanged\ttext\n"):
            with self.subTest(body=body), self.assertRaises(ValueError):
                parse_report(body)

    def test_signed_report_and_replay(self):
        with TemporaryDirectory() as directory:
            state = Path(directory)
            key = "test-key-for-caipc"
            (state / "keys.json").write_text(json.dumps({host: key for host in HOSTS}))
            (state / "addresses.json").write_text(json.dumps({host: "127.0.0.1" for host in HOSTS}))
            server = HTTPServer(("127.0.0.1", 0), make_handler(state, "127.0.0.1"))
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                body = b"service\tDNS\tactive\nalert\t2026-11-11T10:00:00Z\tcheck\tGood\n"
                stamp = str(int(time()))
                signature = hmac.new(key.encode(), stamp.encode() + b"\n" + body, hashlib.sha256).hexdigest()
                url = f"http://127.0.0.1:{server.server_port}"

                def send(sig):
                    request = Request(url + "/ingest", body, {
                        "X-Host": "CAI-DC01", "X-Time": stamp, "X-Signature": sig,
                    })
                    return urlopen(request)

                with self.assertRaises(HTTPError) as bad:
                    send("0" * 64)
                self.assertEqual(bad.exception.code, 400)
                self.assertEqual(send(signature).status, 204)
                report = json.load(urlopen(url + "/api/status"))["CAI-DC01"]
                self.assertEqual(report["services"], {"DNS": "active"})
                with self.assertRaises(HTTPError) as replay:
                    send(signature)
                self.assertEqual(replay.exception.code, 400)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


if __name__ == "__main__":
    unittest.main()
