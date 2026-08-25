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
    status, headers, body = server.request("GET", "/no-such-file.html")
    assert status in (403, 404)


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


def test_unsupported_method_403(server):
    status = server.raw_status(
        b"DELETE /index.html HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"
    )
    assert status == 403
