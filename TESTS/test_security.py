"""Security regression tests.

Each test pins one of the hardening measures from v1.98-v2.05 (CVE fixes
and GHSA drafts). They must keep failing requests failing; the CGI tests
next door prove the same hardening leaves legitimate CGI traffic working.
Raw sockets are used where http.client would refuse to send the request.
"""

import socket
import time

import pytest


def _req(target, extra_headers=b""):
    return (
        b"GET " + target + b" HTTP/1.1\r\nHost: t\r\n" + extra_headers +
        b"Connection: close\r\n\r\n"
    )


# CVE pending (fixed 1.98/2.01): ISINDEX command-line injection.

def test_isindex_shell_metacharacter_rejected(server):
    status = server.raw_status(_req(b"/cgi-bin/envdump.exe?a%26calc.exe"))
    assert status == 400


def test_isindex_leading_hyphen_rejected(server):
    # v2.01: leading '-' would be read as a command-line switch (CWE-88).
    status = server.raw_status(_req(b"/cgi-bin/envdump.exe?-flag"))
    assert status == 400


def test_isindex_quote_rejected(server):
    status = server.raw_status(_req(b"/cgi-bin/envdump.exe?a%22b"))
    assert status == 400


# CVE-2004-2636 and friends: path traversal.

def test_dotdot_traversal_rejected(server):
    status = server.raw_status(_req(b"/../SRC/Tiny.dpr"))
    assert status == 403


def test_encoded_dotdot_traversal_rejected(server):
    status = server.raw_status(_req(b"/%2e%2e/SRC/Tiny.dpr"))
    assert status == 403


def test_backslash_path_rejected(server):
    status = server.raw_status(_req(b"/a\\b.html"))
    assert status == 403


def test_null_byte_in_path_rejected(server):
    status = server.raw_status(_req(b"/a%00b.html"))
    assert status in (400, 403)


# GHSA-wxxh-8845-3c89 (v2.05): control bytes in the decoded URI path.

def test_control_byte_in_path_rejected(server):
    status = server.raw_status(_req(b"/a%01b.html"))
    assert status == 400


# CVE-2024-5193 (v1.99): CRLF injection into the Location header.

def test_crlf_not_reflected_into_location(server):
    data = server.raw(_req(b"/sub%0d%0aX-Evil:1"))
    head = data.split(b"\r\n\r\n", 1)[0]
    assert b"X-Evil" not in head


# CVE-2024-34199 (v1.99): request line and header size limits.

def test_oversized_header_line_rejected(server):
    status = server.raw_status(
        _req(b"/index.html", b"X-Big: " + b"A" * 9000 + b"\r\n")
    )
    assert status in (None, 400)


def test_server_survives_oversized_header(server):
    status, headers, body = server.request("GET", "/index.html")
    assert status == 200


# v2.03: Content-Length strictness on the request side (CWE-444 family).

def test_malformed_request_content_length_rejected(server):
    for bad in (b"abc", b"1 2", b"-1", b"999999999999"):
        payload = (
            b"POST /cgi-bin/postecho.exe HTTP/1.1\r\nHost: t\r\n"
            b"Content-Length: " + bad + b"\r\nConnection: close\r\n\r\n"
        )
        status = server.raw_status(payload)
        assert status in (None, 400), bad


def test_duplicate_request_content_length_rejected(server):
    payload = (
        b"POST /cgi-bin/postecho.exe HTTP/1.1\r\nHost: t\r\n"
        b"Content-Length: 5\r\nContent-Length: 5\r\n"
        b"Connection: close\r\n\r\nhello"
    )
    status = server.raw_status(payload)
    assert status == 400


# GHSA-56x3-254q-j68q (v2.05): unimplemented Transfer-Encoding must 501.

def test_transfer_encoding_chunked_501(server):
    payload = (
        b"POST /cgi-bin/postecho.exe HTTP/1.1\r\nHost: t\r\n"
        b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        b"0\r\n\r\n"
    )
    status = server.raw_status(payload)
    assert status == 501


# v2.04: strict header-line validation (CWE-444 parser differentials).

def test_obs_fold_header_rejected(server):
    status = server.raw_status(
        _req(b"/index.html", b"X-A: 1\r\n \tfolded\r\n")
    )
    assert status == 400


def test_header_name_with_space_rejected(server):
    status = server.raw_status(_req(b"/index.html", b"X A: 1\r\n"))
    assert status == 400


def test_percent_encoded_crlf_in_header_value_rejected(server):
    status = server.raw_status(
        _req(b"/index.html", b"X-A: a%0d%0ab\r\n")
    )
    assert status == 400


# CVE-2026 pending (v2.02): resource-exhaustion limits. Slow by nature.

@pytest.mark.slow
def test_connection_timeout_cuts_off_trickling_client(server):
    # CConnectionTimeoutSecs (30 s) applies to a client that keeps the
    # request alive by trickling bytes, the actual Slowloris shape; the
    # timeout is checked before each socket read, so it only fires while
    # data keeps arriving. A completely silent connection is closed later
    # by the 5-minute resetter thread and is not what this test measures.
    start = time.monotonic()
    closed_at = None
    with socket.create_connection((server.host, server.port), timeout=5) as s:
        s.sendall(b"GET /index.html HTTP/1.1\r\nX-Drip: ")
        s.settimeout(2)
        for _ in range(60):
            try:
                s.sendall(b"a")
            except OSError:
                closed_at = time.monotonic() - start
                break
            try:
                data = s.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                closed_at = time.monotonic() - start
                break
            if data == b"" or b" 408 " in data:
                closed_at = time.monotonic() - start
                break
    assert closed_at is not None, "server never cut off the trickling client"
    assert closed_at < 50, closed_at


def test_server_alive_after_security_tests(server):
    status, headers, body = server.request("GET", "/index.html")
    assert status == 200
