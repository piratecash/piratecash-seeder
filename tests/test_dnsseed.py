"""End-to-end RPC/cache/DNS tests using only local sockets and the Python stdlib."""
import base64
import concurrent.futures
import contextlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest


BINARY = Path(__file__).resolve().parents[1] / "dnsseed"


def node(address, status="ENABLED", **extra):
    return dict(address=address, status=status, **extra)


def response(nodes):
    return json.dumps(dict(result=nodes, error=None, id="dnsseed")).encode()


class RpcServer:
    def __init__(self, nodes):
        self.body = response(nodes)
        self.status = 200
        self.delay = 0
        self.calls = []
        self.condition = threading.Condition()
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with owner.condition:
                    owner.calls.append((request, self.headers.get("Authorization")))
                    body, status, delay = owner.body, owner.status, owner.delay
                    owner.condition.notify_all()
                time.sleep(delay)
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *_):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}/"

    def change(self, body, status=200, delay=0):
        with self.condition:
            self.body, self.status, self.delay = body, status, delay

    def wait_calls(self, count):
        with self.condition:
            if not self.condition.wait_for(lambda: len(self.calls) >= count, timeout=8):
                raise AssertionError(f"Only {len(self.calls)} RPC calls; expected {count}")

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def skip_name(data, offset):
    while data[offset]:
        if data[offset] & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + data[offset]
    return offset + 1


def query(port, qtype=1, host="seed.example.com", ipv6=False):
    name = b"".join(bytes([len(part)]) + part.encode() for part in host.split(".")) + b"\0"
    packet = struct.pack("!6H", 1234, 0x100, 1, 0, 0, 0) + name + struct.pack("!HH", qtype, 1)
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.5)
        sock.sendto(packet, ("::1" if ipv6 else "127.0.0.1", port))
        data = sock.recv(4096)
    ident, flags, _, count, _, _ = struct.unpack("!6H", data[:12])
    assert ident == 1234 and flags & 0x8400 == 0x8400
    offset = skip_name(data, 12) + 4
    addresses, types, ttls = [], [], []
    for _ in range(count):
        offset = skip_name(data, offset)
        typ, cls, ttl, length = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        types.append(typ)
        ttls.append(ttl)
        if typ in (1, 28):
            addresses.append(str(ipaddress.ip_address(data[offset:offset + length])))
        offset += length
    return addresses, types, ttls


class Seeder:
    def __init__(self, rpc, **settings):
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.bind(("::1", 0))
            self.port = sock.getsockname()[1]
        self.directory = tempfile.TemporaryDirectory()
        self.log = tempfile.TemporaryFile()
        values = dict(RPC_URL=rpc.url, RPC_USER="user", RPC_PASSWORD="password123",
                      RPC_POLL_INTERVAL=1, RPC_TIMEOUT=1, DNS_HOST="seed.example.com",
                      DNS_NS="ns.example.com", DNS_MBOX="hostmaster.example.com",
                      DNS_PORT=self.port, DNS_THREADS=4, DNS_TTL=123,
                      BOOTSTRAP_NODES="192.0.2.200,[2001:db8::200]:63636")
        values.update(settings)
        Path(self.directory.name, ".env").write_text("\n".join(f'{k}="{v}"' for k, v in values.items()))
        # Exercise .env loading without inheriting deployment settings.
        env = {k: v for k, v in os.environ.items() if not k.startswith(("DNS_", "RPC_", "BOOTSTRAP_"))}
        self.process = subprocess.Popen([str(BINARY)], cwd=self.directory.name,
                                        stdout=self.log, stderr=self.log, env=env)

    def wait_addresses(self, expected, qtype=1):
        deadline = time.monotonic() + 8
        actual = None
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.log.seek(0)
                raise AssertionError(self.log.read().decode())
            try:
                actual = query(self.port, qtype)[0]
                if set(actual) == set(expected):
                    return
            except (TimeoutError, socket.timeout):
                pass
            time.sleep(0.03)
        raise AssertionError(f"Expected {expected}, got {actual}")

    def close(self):
        self.process.terminate()
        self.process.wait(timeout=5)
        self.log.close()
        self.directory.cleanup()


class DnsSeedTest(unittest.TestCase):
    @contextlib.contextmanager
    def running(self, nodes, **settings):
        rpc = RpcServer(nodes)
        seeder = None
        try:
            seeder = Seeder(rpc, **settings)
            yield rpc, seeder
        finally:
            if seeder:
                seeder.close()
            rpc.close()

    def test_active_only_randomized_deduplicated_and_no_rpc_per_query(self):
        nodes = {str(i): node(f"192.0.2.{i}:63636") for i in range(1, 81)}
        nodes.update(banned=node("192.0.2.201:63636", "POSE_BANNED"),
                     unknown=node("192.0.2.202:63636", "PRE_ENABLED"),
                     duplicate=node("192.0.2.1:63636"),
                     ipv6=node("[2001:db8::1]:63636"),
                     hostname=node("example.com:63636"),
                     unspecified=node("0.0.0.0:0"))
        with self.running(nodes, RPC_POLL_INTERVAL=60) as (rpc, seeder):
            seeder.wait_addresses(["2001:db8::1"], 28)
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                answers = list(pool.map(lambda _: query(seeder.port), range(80)))
            allowed = {f"192.0.2.{i}" for i in range(1, 81)}
            for addresses, types, ttls in answers:
                self.assertTrue(addresses)
                self.assertTrue(set(addresses) <= allowed)
                self.assertEqual(len(addresses), len(set(addresses)))
                self.assertEqual(set(ttls), {123})
                self.assertEqual(set(types), {1})
            self.assertGreater(len({tuple(a[0]) for a in answers}), 1)
            self.assertEqual(len(rpc.calls), 1)
            request, authorization = rpc.calls[0]
            self.assertEqual(request["method"], "masternode")
            self.assertEqual(request["params"], ["list", "json"])
            self.assertEqual(authorization, "Basic " + base64.b64encode(b"user:password123").decode())
            self.assertEqual(query(seeder.port, host="x1.seed.example.com")[0], [])
            self.assertEqual(query(seeder.port, 2)[1], [2])
            self.assertEqual(query(seeder.port, 6)[1], [6])
            self.assertTrue(query(seeder.port, ipv6=True)[0])

    def test_core_p2p_addresses_preferred_over_platform_and_legacy(self):
        nodes = {"modern": node("192.0.2.99:443", addresses={
                    "core_p2p": ["192.0.2.1:63636", "[2001:db8::1]:63636"],
                    "platform_https": ["192.0.2.98:443"]}),
                 "modern_without_legacy": {"status": "ENABLED", "addresses": {"core_p2p": ["192.0.2.2:63636"]}},
                 "mapped_duplicate": node("[::ffff:192.0.2.1]:63636"),
                 "banned": node("192.0.2.3:63636", "POSE_BANNED")}
        with self.running(nodes) as (_, seeder):
            seeder.wait_addresses(["192.0.2.1", "192.0.2.2"])
            seeder.wait_addresses(["2001:db8::1"], 28)

    def test_rpc_failures_keep_cache_then_recovery_removes_banned_nodes(self):
        nodes = {"first": node("192.0.2.1:63636")}
        with self.running(nodes) as (rpc, seeder):
            seeder.wait_addresses(["192.0.2.1"])
            for body, status in [(b"down", 503), (b"{broken", 200),
                                 (b'{"error":{"code":-28},"result":null}', 200),
                                 (b'{"error":null,"result":[]}', 200),
                                 (response({"bad": {"status": "ENABLED", "addresses": {"core_p2p": 42}}}), 200)]:
                target = len(rpc.calls) + 1
                rpc.change(body, status)
                rpc.wait_calls(target)
                time.sleep(0.08)
                self.assertEqual(query(seeder.port)[0], ["192.0.2.1"])
            rpc.change(response({"first": node("192.0.2.1:63636", "POSE_BANNED"),
                                 "second": node("192.0.2.2:63636")}))
            seeder.wait_addresses(["192.0.2.2"])

    def test_startup_failure_uses_bootstrap_then_recovers(self):
        rpc = RpcServer({})
        rpc.change(b"unavailable", 503)
        seeder = Seeder(rpc)
        try:
            seeder.wait_addresses(["192.0.2.200"])
            seeder.wait_addresses(["2001:db8::200"], 28)
            rpc.change(response({"active": node("192.0.2.1:63636")}))
            seeder.wait_addresses(["192.0.2.1"])
        finally:
            seeder.close()
            rpc.close()

    def test_successful_empty_list_replaces_banned_cache_with_bootstrap(self):
        with self.running({"first": node("192.0.2.1:63636")}) as (rpc, seeder):
            seeder.wait_addresses(["192.0.2.1"])
            rpc.change(response({"first": node("192.0.2.1:63636", "POSE_BANNED")}))
            seeder.wait_addresses(["192.0.2.200"])
            rpc.change(response({}))
            seeder.wait_addresses(["192.0.2.200"])

    def test_timeout_does_not_block_dns_or_replace_cache(self):
        with self.running({"first": node("192.0.2.1:63636")}) as (rpc, seeder):
            seeder.wait_addresses(["192.0.2.1"])
            target = len(rpc.calls) + 1
            rpc.change(response({"new": node("192.0.2.2:63636")}), delay=2)
            rpc.wait_calls(target)
            started = time.monotonic()
            for _ in range(10):
                self.assertEqual(query(seeder.port)[0], ["192.0.2.1"])
            self.assertLess(time.monotonic() - started, 0.5)
            time.sleep(1.1)
            self.assertEqual(query(seeder.port)[0], ["192.0.2.1"])

    def test_connection_refused_uses_bootstrap(self):
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            url = f"http://127.0.0.1:{unused.getsockname()[1]}/"
            # The bound socket is deliberately not listening for connections.
            with self.running({}, RPC_URL=url) as (_, seeder):
                seeder.wait_addresses(["192.0.2.200"])

    def test_empty_cache_without_bootstrap_returns_no_addresses(self):
        with self.running({}, BOOTSTRAP_NODES="") as (_, seeder):
            seeder.wait_addresses([])
            seeder.wait_addresses([], 28)

    def test_invalid_config_fails_before_serving(self):
        for setting in ({"DNS_PORT": "bad"}, {"RPC_POLL_INTERVAL": 0},
                        {"BOOTSTRAP_NODES": "hostname.example.com"}):
            with self.subTest(setting=setting), self.running({}, **setting) as (_, seeder):
                self.assertEqual(seeder.process.wait(timeout=3), 1)


if __name__ == "__main__":
    unittest.main()
