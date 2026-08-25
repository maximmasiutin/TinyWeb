# TinyWeb Test Suite

Integration tests that run the real `Tiny.exe` against a scratch webroot and drive it over HTTP. They exist because of a field regression: versions 2.03 through 2.05 rejected every CGI response that carried no `Content-Length` header, which RFC 3875 Section 6.3 makes optional, so every classic CGI (including every example in `CGITEST/`) answered `500 Internal Server Error` while version 1.99 worked. The suite pins both directions: the security hardening from v1.98-v2.05 must keep rejecting what it rejects, and legitimate CGI traffic must keep working.

## Layout

| Path | Purpose |
| --- | --- |
| `conftest.py` | Builds fixtures, assembles a webroot under `_work/` (not a dot-name: Wine reports dot-directories as hidden and TinyWeb refuses hidden directories), starts the server on a free port. |
| `build_fixtures.py` | Compiles `cgi/*.pas` (FPC), `CGITEST/login.dpr` (FPC in Delphi mode), and `CGITEST/hello.c`, `helloh.c` (gcc, optional). Also runnable directly to pre-build for the container lane. |
| `cgi/*.pas` | Purpose-built CGI fixtures; each file's header comment states its contract. |
| `test_cgi.py` | CGI behavior: the Content-Length regression, QUERY_STRING, ISINDEX arguments, POST to stdin, Status and Location directives, the CGITEST examples. |
| `test_static.py` | Static serving baseline: index, HEAD, redirects, If-Modified-Since. |
| `test_security.py` | One test per hardening measure from v1.98-v2.05 (CVE and GHSA fixes). |
| `Dockerfile`, `run_container.ps1` | Wine container lane. |

## Running

Local (Windows, FPC 3.2.2 installed):

```text
SRC> fpc -B -MObjFPC Tiny.dpr
> python -m pip install pytest
> python -m pytest TESTS
```

`build_fixtures.py` finds the compiler through the `FPC` environment variable, then `fpc` on `PATH`. `TINYWEB_EXE` overrides the server binary under test.

CI: `.github/workflows/tests.yml` runs the suite on `windows-latest` for every push to `master` and every pull request touching `SRC/`, `CGITEST/`, or `TESTS/`, including the slow resource-limit tests.

Container (Docker in Linux-containers mode; binaries are built on the Windows host, the suite runs them under Wine):

```text
> powershell -File TESTS\run_container.ps1
```

## Markers and skips

- `slow`: resource-limit tests (connection timeout); excluded with `-m "not slow"`.
- The `CGITEST` C examples need a working `gcc` (present on GitHub runners); without one those tests skip.
- `CGITEST/hello.pl` is not tested: launching `.pl` files depends on a per-machine file association, which test machines do not have.

## Behavior notes the tests pin

- A missing static file answers 403, not 404: `LocalFNameSafe` refuses paths it cannot validate before any not-found distinction is made.
- The CGI `Location` directive is tested in its absolute-URL form (302). The local-path form goes through `OpenRequestedFile` with a webroot-relative name and has not worked in any surveyed version.
- A CGI response with a present but malformed or duplicated `Content-Length` stays a 500; only the absent header is legal.
