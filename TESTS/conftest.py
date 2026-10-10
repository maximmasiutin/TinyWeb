"""Session fixtures: build the fixtures, assemble webroots, run Tiny.exe.

Environment knobs:
- TINYWEB_EXE: path to the server binary (default: SRC/Tiny.exe).
- FPC: path to the Free Pascal compiler used for fixture builds.
- TINYWEB_WINE=1: run the Windows binaries through Wine (container lane).
  In this mode nothing is compiled; TESTS/_work/bin must already hold the
  fixture binaries (python TESTS/build_fixtures.py on a Windows host).
"""

import http.client
import os
import secrets
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

import build_fixtures as bf

WINE = os.environ.get("TINYWEB_WINE") == "1"

STATIC_INDEX = "tinyweb-static-index\n"
STATIC_PAGE = "tinyweb-static-page\n"
STATIC_SUB = "tinyweb-static-subdir-index\n"
# Content of a non-executable file under cgi-bin; it must never reach a client.
CGI_MARKER = "tinyweb-cgi-file-" + secrets.token_hex(16)
# Static file holding a per-start token; a 200 carrying it proves the answer
# came from the server just started.
READY_FILE = "ready.txt"
STARTUP_SECS = 120 if WINE else 20


def host_path(p):
    """Path as the server binary sees it (Wine maps the root to Z:)."""
    p = str(p)
    if WINE:
        return "Z:" + p.replace("/", "\\")
    return p


class ServerEnv:
    def __init__(self, port, webroot, caps, proc, logdir):
        self.port = port
        self.webroot = webroot
        self.caps = caps
        self.proc = proc
        self.cgi_marker = CGI_MARKER.encode("ascii")
        self.logdir = logdir
        self.host = "127.0.0.1"

    def request(self, method, target, body=None, headers=None, timeout=30):
        """One HTTP request; returns (status, headers-dict, body-bytes)."""
        conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        try:
            hdrs = {"Connection": "close"}
            if headers:
                hdrs.update(headers)
            conn.request(method, target, body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read()
            # resp.headers keeps case-insensitive lookup, which is what
            # HTTP field names have; a plain dict would not.
            return resp.status, resp.headers, data
        finally:
            conn.close()

    def raw(self, payload, timeout=15):
        """Send raw bytes, return everything the server answers."""
        chunks = []
        with socket.create_connection((self.host, self.port), timeout=timeout) as s:
            s.sendall(payload)
            s.settimeout(timeout)
            try:
                while True:
                    b = s.recv(65536)
                    if not b:
                        break
                    chunks.append(b)
            except socket.timeout:
                pass
        return b"".join(chunks)

    def raw_status(self, payload, timeout=15):
        """Status code of a raw exchange, or None for no/invalid answer."""
        data = self.raw(payload, timeout)
        line = data.split(b"\r\n", 1)[0]
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith(b"HTTP/"):
            try:
                return int(parts[1])
            except ValueError:
                return None
        return None


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _assemble_webroot(root):
    if root.exists():
        shutil.rmtree(root)
    (root / "cgi-bin").mkdir(parents=True)
    (root / "sub").mkdir()
    (root / "index.html").write_text(STATIC_INDEX)
    (root / "page.html").write_text(STATIC_PAGE)
    (root / "sub" / "index.html").write_text(STATIC_SUB)
    (root / "cgi-bin" / "secret.txt").write_text(CGI_MARKER)
    for exe in bf.BIN.glob("*.exe"):
        shutil.copy2(exe, root / "cgi-bin" / exe.name)


class StartupError(Exception):
    pass


def _stop(proc):
    """Kill the server if it still runs and wait until it has exited."""
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=30)


def _diagnostics(cmd, proc, logdir, reason):
    out = [
        "server startup failed: %s" % reason,
        "command: %s" % " ".join(cmd),
        "exit code: %s" % proc.returncode,
    ]
    for f in sorted(logdir.iterdir()):
        if f.is_file():
            data = f.read_bytes()[-2000:]
            out.append("--- %s (last %d bytes)" % (f.name, len(data)))
            out.append(data.decode("latin-1"))
    return "\n".join(out)


def _start_server(exe, webroot, logdir, caps):
    """Start Tiny.exe on webroot bound to 127.0.0.1; return a ServerEnv once
    READY_FILE answers with this start's token, else raise StartupError."""
    logdir.mkdir(parents=True, exist_ok=True)
    token = "tinyweb-ready-" + secrets.token_hex(8)
    (webroot / READY_FILE).write_text(token)
    port = _free_port()
    # The third argument is the bind address. Without it TinyWeb listens on
    # every interface; a test server never needs more than loopback.
    cmd = [str(exe), host_path(webroot), str(port), "127.0.0.1"]
    if WINE:
        cmd = ["wine"] + cmd
    with open(logdir / "console.txt", "wb") as console:
        proc = subprocess.Popen(
            cmd,
            cwd=logdir,
            stdin=subprocess.DEVNULL,
            stdout=console,
            stderr=subprocess.STDOUT,
        )

    env = ServerEnv(port, webroot, caps, proc, logdir)
    reason = "no ready answer within %d s" % STARTUP_SECS
    deadline = time.monotonic() + STARTUP_SECS
    try:
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                reason = "server exited early"
                break
            try:
                status, headers, body = env.request(
                    "GET", "/" + READY_FILE, timeout=2
                )
            except (OSError, http.client.HTTPException) as e:
                reason = "last probe error: %r" % e
            else:
                name = headers.get("Server", "")
                if (status == 200 and body == token.encode("ascii")
                        and name.startswith("TinyWeb/")):
                    return env
                reason = "probe answered %s, Server %r, body %r" % (
                    status, name, body[:80])
            time.sleep(0.2)
    except BaseException:
        _stop(proc)
        raise
    _stop(proc)
    raise StartupError(_diagnostics(cmd, proc, logdir, reason))


@pytest.fixture(scope="session")
def server_exe():
    exe = Path(os.environ.get("TINYWEB_EXE", bf.REPO / "SRC" / "Tiny.exe"))
    if not exe.is_file():
        pytest.exit(
            "server binary not found: %s (build it first, or set TINYWEB_EXE)" % exe
        )
    return exe


@pytest.fixture(scope="session")
def fixture_caps():
    """Build the CGI fixtures once per session; every server shares them."""
    caps = {"gcc": False, "login": False}
    if WINE:
        if not any(bf.BIN.glob("*.exe")):
            pytest.exit(
                "TESTS/_work/bin holds no fixture binaries; run "
                "python TESTS/build_fixtures.py on a Windows host first"
            )
        caps["gcc"] = (bf.BIN / "hello.exe").is_file()
        caps["login"] = (bf.BIN / "login.exe").is_file()
    else:
        caps = bf.build_all()
    return caps


@pytest.fixture(scope="session")
def server(server_exe, fixture_caps):
    webroot = bf.WORK / "webroot"
    _assemble_webroot(webroot)
    try:
        env = _start_server(server_exe, webroot, bf.WORK / "logs", fixture_caps)
    except StartupError as e:
        pytest.exit(str(e))
    try:
        yield env
    finally:
        _stop(env.proc)


@pytest.fixture(scope="module")
def mixedcase_server(server_exe, fixture_caps):
    """A second server on the mixed-case root _work/MixedCase/WebRoot, with
    its own log directory."""
    base = bf.WORK / "MixedCase"
    webroot = base / "WebRoot"
    _assemble_webroot(webroot)
    try:
        env = _start_server(server_exe, webroot, base / "logs", fixture_caps)
    except StartupError as e:
        pytest.fail(str(e), pytrace=False)
    try:
        yield env
    finally:
        _stop(env.proc)
