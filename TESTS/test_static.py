"""Static file serving: the baseline the CGI tests stand on."""

import socket


def test_index_file(server):
    status, headers, body = server.request("GET", "/index.html")
    assert status == 200
    assert b"tinyweb-static-index" in body


def test_named_file(server):
    status, headers, body = server.request("GET", "/page.html")
    assert status == 200
    assert b"tinyweb-static-page" in body


def test_missing_file_rejected(server):
    # TinyWeb answers 403 for a missing file: LocalFNameSafe cannot stat the
    # path, and the safety refusal comes before any not-found distinction.
    # Pinned exactly; a deliberate change to 404 updates this test with it.
    status, headers, body = server.request("GET", "/no-such-file.html")
    assert status == 403


def test_head_returns_no_body(server):
    status, headers, body = server.request("HEAD", "/page.html")
    assert status == 200
    assert body == b""


def test_extensionless_path_redirects(server):
    status, headers, body = server.request("GET", "/sub")
    assert status == 302
    assert headers.get("Location", "").endswith("/sub/")


def test_subdirectory_index(server):
    status, headers, body = server.request("GET", "/sub/")
    assert status == 200
    assert b"tinyweb-static-subdir-index" in body


def test_if_modified_since_304(server):
    status, headers, body = server.request("GET", "/page.html")
    assert status == 200
    lm = headers.get("Last-Modified")
    assert lm
    status2, headers2, body2 = server.request(
        "GET", "/page.html", headers={"If-Modified-Since": lm}
    )
    assert status2 == 304
    assert body2 == b""


def test_304_carries_no_body_on_the_wire(server):
    # RFC 9110 Section 15.4.5: 304 must not carry content. http.client
    # suppresses 304 bodies, so this check reads the raw bytes instead;
    # routing 304 through the error path used to attach an HTML body.
    status, headers, body = server.request("GET", "/page.html")
    lm = headers.get("Last-Modified")
    assert lm
    raw = server.raw(
        b"GET /page.html HTTP/1.1\r\nHost: t\r\n"
        b"If-Modified-Since: " + lm.encode() + b"\r\n"
        b"Connection: close\r\n\r\n"
    )
    head, sep, tail = raw.partition(b"\r\n\r\n")
    assert b" 304 " in head.split(b"\r\n", 1)[0]
    assert tail == b""


def test_head_error_page_carries_no_body(server):
    # RFC 9110 Section 9.3.2: the generated error page is content as well.
    raw = server.raw(
        b"HEAD /no-such-file.html HTTP/1.1\r\nHost: t\r\n"
        b"Connection: close\r\n\r\n"
    )
    head, sep, tail = raw.partition(b"\r\n\r\n")
    assert b" 403 " in head.split(b"\r\n", 1)[0], head
    assert tail == b""


def test_head_keeps_keep_alive_framing(server):
    # On a kept-alive connection a body after the HEAD header would be read
    # as the start of the next answer.
    buf = b""
    with socket.create_connection((server.host, server.port), timeout=15) as s:
        s.sendall(b"HEAD /page.html HTTP/1.1\r\nHost: t\r\n"
                  b"Connection: Keep-Alive\r\n\r\n")
        while b"\r\n\r\n" not in buf:
            b = s.recv(65536)
            assert b, buf
            buf += b
        s.sendall(b"GET /page.html HTTP/1.1\r\nHost: t\r\n"
                  b"Connection: close\r\n\r\n")
        while True:
            b = s.recv(65536)
            if not b:
                break
            buf += b
    head, sep, tail = buf.partition(b"\r\n\r\n")
    assert b" 200 " in head.split(b"\r\n", 1)[0], head
    assert b"Keep-Alive" in head, head
    assert tail.startswith(b"HTTP/1.0 200 "), tail[:80]
    assert b"tinyweb-static-page" in tail.partition(b"\r\n\r\n")[2], tail


def test_unsupported_method_403(server):
    status = server.raw_status(
        b"DELETE /index.html HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"
    )
    assert status == 403
