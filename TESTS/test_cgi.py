"""CGI behavior tests.

The first test is the regression that broke every classic CGI in
v2.03-v2.05: a CGI response without Content-Length (RFC 3875 makes the
header optional) was rejected by DoCollect's strict numeric validation and
turned into 500 Internal Server Error. All CGITEST examples respond without
Content-Length, so they are used here as fixtures unchanged.
"""

import pytest


def test_cgi_response_without_content_length(server):
    # Regression: v2.03..v2.05 answered 500 here.
    status, headers, body = server.request("GET", "/cgi-bin/envdump.exe")
    assert status == 200, body
    assert b"envdump-marker" in body
    assert b"REQUEST_METHOD=GET" in body


def test_cgi_response_with_content_length(server):
    status, headers, body = server.request("GET", "/cgi-bin/clenresp.exe")
    assert status == 200, body
    assert b"clenresp-marker" in body


def test_query_string_reaches_environment(server):
    status, headers, body = server.request("GET", "/cgi-bin/envdump.exe?a=1&b=2")
    assert status == 200, body
    assert b"QUERY_STRING=a=1&b=2" in body
    # A query containing '=' is NOT an ISINDEX query: no command-line args.
    assert b"ARGC=0" in body


def test_isindex_query_becomes_argument(server):
    # RFC 3875 Section 4.4: a query without '=' is passed as a command line.
    status, headers, body = server.request("GET", "/cgi-bin/envdump.exe?searchword")
    assert status == 200, body
    assert b"QUERY_STRING=searchword" in body
    assert b"ARGC=1" in body
    assert b"ARGV1=searchword" in body


def test_isindex_safe_characters_accepted(server):
    # The STRICT_CGI_PARAMS whitelist must keep legitimate ISINDEX
    # queries working: security hardening, not CGI breakage.
    status, headers, body = server.request("GET", "/cgi-bin/envdump.exe?abc_1.2:x")
    assert status == 200, body
    assert b"ARGV1=abc_1.2:x" in body


def test_http_headers_mapped_to_environment(server):
    status, headers, body = server.request(
        "GET",
        "/cgi-bin/envdump.exe",
        headers={"User-Agent": "tinyweb-suite", "Cookie": "k=v"},
    )
    assert status == 200, body
    assert b"HTTP_USER_AGENT=tinyweb-suite" in body
    assert b"HTTP_COOKIE=k=v" in body
    assert b"GATEWAY_INTERFACE=CGI/1.1" in body
    assert b"SCRIPT_NAME=/cgi-bin/envdump.exe" in body


def test_post_body_reaches_stdin(server):
    payload = (b"x=" + b"a" * 65534)  # 64 KiB total
    status, headers, body = server.request(
        "POST",
        "/cgi-bin/postecho.exe",
        body=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status == 200, body
    assert ("postecho-bytes=%d" % len(payload)).encode() in body
    assert payload in body


def test_status_directive_sets_http_status(server):
    status, headers, body = server.request("GET", "/cgi-bin/statusdir.exe")
    assert status == 404, body
    assert b"statusdir-marker" in body


def test_location_directive_url(server):
    status, headers, body = server.request("GET", "/cgi-bin/locdir.exe")
    assert status == 302, body
    assert headers.get("Location") == "http://example.invalid/moved"


def test_duplicate_content_length_response_rejected(server):
    # RFC 9110 Section 8.6 strictness on the CGI response side must stay.
    status, headers, body = server.request("GET", "/cgi-bin/dupclen.exe")
    assert status == 500, body


def test_malformed_content_length_response_rejected(server):
    status, headers, body = server.request("GET", "/cgi-bin/badclen.exe")
    assert status == 500, body


def test_cgitest_hello_c(server):
    if not server.caps["gcc"]:
        pytest.skip("gcc not available: CGITEST C examples not built")
    status, headers, body = server.request("GET", "/cgi-bin/hello.exe")
    assert status == 200, body
    assert b"Hello, world" in body


def test_cgitest_helloh_c(server):
    if not server.caps["gcc"]:
        pytest.skip("gcc not available: CGITEST C examples not built")
    status, headers, body = server.request("GET", "/cgi-bin/helloh.exe")
    assert status == 200, body
    assert b"<H1>Hello, world!</H1>" in body


def test_cgitest_login_post_flow(server):
    if not server.caps["login"]:
        pytest.skip("login.dpr fixture not built")
    form = b"userid=Jimmi&password=Hendrix"
    status, headers, body = server.request(
        "POST",
        "/cgi-bin/login.exe",
        body=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status == 200, body
    assert b"successfully logged in" in body


def test_server_alive_after_cgi_tests(server):
    status, headers, body = server.request("GET", "/index.html")
    assert status == 200
