"""Static file serving: the baseline the CGI tests stand on."""


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


def test_unsupported_method_403(server):
    status = server.raw_status(
        b"DELETE /index.html HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"
    )
    assert status == 403
