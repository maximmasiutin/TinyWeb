"""Session fixtures: build the fixtures, assemble a webroot, run Tiny.exe.

Environment knobs:
- TINYWEB_EXE: path to the server binary (default: SRC/Tiny.exe).
- FPC: path to the Free Pascal compiler used for fixture builds.
- TINYWEB_WINE=1: run the Windows binaries through Wine (container lane).
  In this mode nothing is compiled; TESTS/.work/bin must already hold the
  fixture binaries (python TESTS/build_fixtures.py on a Windows host).
"""

import http.client
import os
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
        self.logdir = logdir
        self.host = "127.0.0.1"

    def request(self, method, target, body=None, headers=None):
        """One HTTP request; returns (status, headers-dict, body-bytes)."""
        conn = http.client.HTTPConnection(self.host, self.port, timeout=30)
        try:
            hdrs = {"Connection": "close"}
            if headers:
                hdrs.update(headers)
            conn.request(method, target, body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, dict(resp.getheaders()), data
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
    for exe in bf.BIN.glob("*.exe"):
        shutil.copy2(exe, root / "cgi-bin" / exe.name)


@pytest.fixture(scope="session")
def server():
    exe = Path(os.environ.get("TINYWEB_EXE", bf.REPO / "SRC" / "Tiny.exe"))
    if not exe.is_file():
        pytest.exit(
            "server binary not found: %s (build it first, or set TINYWEB_EXE)" % exe
        )

    caps = {"gcc": False, "login": False}
    if WINE:
        if not any(bf.BIN.glob("*.exe")):
            pytest.exit(
                "TESTS/.work/bin holds no fixture binaries; run "
                "python TESTS/build_fixtures.py on a Windows host first"
            )
        caps["gcc"] = (bf.BIN / "hello.exe").is_file()
        caps["login"] = (bf.BIN / "login.exe").is_file()
    else:
        caps = bf.build_all()

    webroot = bf.WORK / "webroot"
    _assemble_webroot(webroot)
    logdir = bf.WORK / "logs"
    logdir.mkdir(parents=True, exist_ok=True)

    port = _free_port()
    cmd = [str(exe), host_path(webroot), str(port)]
    if WINE:
        cmd = ["wine"] + cmd
    proc = subprocess.Popen(
        cmd,
        cwd=logdir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    env = ServerEnv(port, webroot, caps, proc, logdir)
    deadline = time.monotonic() + (120 if WINE else 20)
    last_err = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            pytest.exit("server exited early with code %s" % proc.returncode)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                break
        except OSError as e:
            last_err = e
            time.sleep(0.2)
    else:
        proc.kill()
        pytest.exit("server did not accept connections: %s" % last_err)

    yield env

    proc.kill()
    proc.wait(timeout=10)
