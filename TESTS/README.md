# TinyWeb Test Suite

Integration tests that run the real `Tiny.exe` against a scratch webroot and drive it over HTTP. They exist because of a field regression: versions 2.03 through 2.05 rejected every CGI response that carried no `Content-Length` header, which RFC 3875 Section 6.3 makes optional, so every classic CGI (including every example in `CGITEST/`) answered `500 Internal Server Error` while version 1.99 worked. The suite pins both directions: the security hardening from v1.98-v2.05 must keep rejecting what it rejects, and legitimate CGI traffic must keep working.

## Layout

| Path | Purpose |
| --- | --- |
| `conftest.py` | Builds fixtures once per session, assembles a webroot under `_work/` (not a dot-name: Wine reports dot-directories as hidden and TinyWeb refuses hidden directories), starts the server bound to `127.0.0.1` on a free port, so a test run never listens beyond loopback, and waits for a 200 carrying a per-start token. A second, module-scoped server runs on the mixed-case root `_work/MixedCase/WebRoot` with its own log directory. |
| `build_fixtures.py` | Compiles `cgi/*.pas` (FPC), `CGITEST/login.dpr` (FPC in Delphi mode), and `CGITEST/hello.c`, `helloh.c` (gcc, optional). Also runnable directly to pre-build for the container lane. |
| `cgi/*.pas` | Purpose-built CGI fixtures; each file's header comment states its contract. |
| `test_cgi.py` | CGI behavior: the Content-Length regression, QUERY_STRING, ISINDEX arguments, POST to stdin, Status and Location directives, the CGITEST examples. |
| `test_static.py` | Static serving baseline: index, HEAD, redirects, If-Modified-Since. |
| `test_security.py` | One test per hardening measure from v1.98-v2.05 (CVE and GHSA fixes). |
| `test_containment.py` | What the static-file routine may send: CGI `Location` values with a filesystem path (regressions, existing protections, compatibility cases and documented changes, plus a deterministic corpus of spellings), the URI route around `cgi-bin`, junctions and symbolic links, the HEAD answer of both routes, and the server's handle count across refusals. |
| `Dockerfile`, `run_container.ps1` | Wine container lane. |
| `unit/xbtest.dpr` | Unit tests for every testable free function of `SRC/xBase.pas`, the `TColl`/`TSortedColl`/`TStringColl` family, and smoke tests for the OS-bound wrappers. |
| `unit/srvtest.dpr` | Unit tests for the pure `SRC/SrvMain.pas` parsers (date parsing, header strictness, log escaping, CGI parameter escaping, address parsing), reached through interface declarations added for this purpose. |

## Running

Local (Windows, FPC 3.2.2 installed):

```text
SRC> fpc -B -MObjFPC Tiny.dpr
> python -m pip install pytest
> python -m pytest TESTS
```

`build_fixtures.py` finds the compiler through the `FPC` environment variable, then `fpc` on `PATH`. `TINYWEB_EXE` overrides the server binary under test.

CI: `.github/workflows/tests.yml` runs the suite on `windows-latest` for every push to `master` and every pull request touching `SRC/`, `CGITEST/`, or `TESTS/`, including the slow resource-limit tests. Before pytest it compiles and runs the two unit-test programs in both compiler modes:

```text
TESTS\unit> fpc -B -MObjFPC -Fu..\..\SRC -Fi..\..\SRC xbtest.dpr && xbtest
TESTS\unit> fpc -B -MObjFPC -Fu..\..\SRC -Fi..\..\SRC srvtest.dpr && srvtest
```

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
- The CGI `Location` directive has two accepted forms. An absolute URL whose RFC 3986 scheme starts the value answers 302. An absolute Windows filesystem path (`C:\www\page.html`), a TinyWeb extension and not an RFC 3875 Section 6.2.2 local redirect, is sent by `OpenRequestedFile` only when it is spelled canonically (drive letter, single backslashes, no `.` or `..`, no trailing dot or space in any component, no colon past the drive, no device name), lies inside the web root and outside `cgi-bin`, and the opened file's final path, after links, junctions and 8.3 names, does too; otherwise 403. Every other value answers 403, including a webroot-relative URL path (`/page.html`, the RFC local-redirect form, still unsupported) and a value with `://` later in it. A forward slash in a filesystem path is refused rather than normalized, a change from earlier versions, which served it.
- A junction or link under the web root is followed only when its target lies inside the web root and outside `cgi-bin`.
- A HEAD answer still carries the file after the header, on both routes, which RFC 9110 Section 9.3.2 forbids; `test_containment.py::test_head_sends_no_body` is a strict expected failure until that is fixed.
- A CGI response with a present but malformed or duplicated `Content-Length` stays a 500; only the absent header is legal.
