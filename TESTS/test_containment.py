"""Files OpenRequestedFile may send, probed via loclocal.exe?target=file on
mixedcase_server; TINYWEB_PROBE_TABLE=<file> records each probe's result."""

import ctypes
import os
import sys

import pytest

from conftest import CGI_MARKER, WINE, host_path

CGI_FILE_MARKER = CGI_MARKER.encode("ascii")
SIBLING = b"tinyweb-sibling-marker"
PAGE = b"tinyweb-static-page"
SUB = b"tinyweb-static-subdir-index"

REG = "regression"
PROT = "protection"
COMPAT = "compatibility"
CHANGE = "change"

DENY = ("deny", None)
REDIRECT_URL = "http://example.invalid/moved"
REDIRECT = ("redirect", REDIRECT_URL)


def serve(marker):
    return ("serve", marker)


def disclosed(body):
    """True when the body carries protected content."""
    return body[:2] == b"MZ" or CGI_FILE_MARKER in body or SIBLING in body


def _encode(value):
    # The server reads CGI header bytes in its ANSI code page.
    return value.encode("mbcs" if sys.platform == "win32" else "utf-8")


def _record(cls, case_id, status, body):
    path = os.environ.get("TINYWEB_PROBE_TABLE")
    if not path:
        return
    with open(path, "a", encoding="ascii", errors="backslashreplace") as f:
        f.write("%s\t%s\t%s\t%s\n" % (
            cls, case_id, status, "DISCLOSED" if disclosed(body) else "-"))


def _problem(case_id, expect, result):
    """None when the answer meets the expectation, else a description."""
    status, headers, body = result
    if disclosed(body):
        return "%s: protected content sent with status %s" % (case_id, status)
    kind, arg = expect
    if kind == "deny" and status != 403:
        return "%s: status %s, want 403" % (case_id, status)
    if kind == "serve" and not (status == 200 and arg in body):
        return "%s: status %s, want 200 with %r" % (case_id, status, arg)
    if kind == "redirect" and not (
            status == 302 and headers.get("Location") == arg):
        return "%s: status %s, Location %r, want 302 to %s" % (
            case_id, status, headers.get("Location"), arg)
    return None


def check(cls, case_id, expect, result):
    _record(cls, case_id, result[0], result[2])
    problem = _problem(case_id, expect, result)
    assert problem is None, problem


class Box:
    """The mixed-case server, its host-side root, a prefix-sharing sibling
    directory and the file holding the next Location value."""

    def __init__(self, env):
        self.env = env
        self.root = env.webroot
        self.R = host_path(self.root)
        self.sibling = self.root.parent / (self.root.name + "-sibling")
        self.value_file = self.root / "cgi-bin" / "loclocal.txt"

    def location(self, value):
        self.value_file.write_bytes(_encode(value))
        return self.env.request("GET", "/cgi-bin/loclocal.exe?target=file")

    def get(self, target):
        return self.env.request("GET", target)


@pytest.fixture(scope="module")
def box(mixedcase_server):
    assert mixedcase_server.cgi_marker == CGI_FILE_MARKER
    b = Box(mixedcase_server)
    b.sibling.mkdir(exist_ok=True)
    (b.sibling / "marker.txt").write_bytes(SIBLING + b"\n")
    return b


def location_cases(R, root_name):
    drive, rest = R[:2], R[2:]
    other = "D:" if drive.upper() == "C:" else "C:"
    return [
        # Regressions: dot segments, mixed separators, a prefix-sharing
        # sibling and other spellings Windows opens as a file in cgi-bin.
        ("dotdot-secret", REG, R + r"\sub\..\cgi-bin\secret.txt", DENY),
        ("dotdot-exe", REG, R + r"\sub\..\cgi-bin\loclocal.exe", DENY),
        ("mixedsep-secret", REG, R + r"\cgi-bin/secret.txt", DENY),
        ("mixedsep-exe", REG, R + r"\cgi-bin/loclocal.exe", DENY),
        ("sibling-prefix", REG, R + r"-sibling\marker.txt", DENY),
        ("outside-dotdot", REG,
         R + "\\..\\" + root_name + r"-sibling\marker.txt", DENY),
        ("dot-segment", REG, R + r"\.\cgi-bin\secret.txt", DENY),
        ("forward-dotdot", REG, R + "/sub/../cgi-bin/secret.txt", DENY),
        ("trailing-dot-dir", REG, R + r"\cgi-bin.\secret.txt", DENY),
        ("root-doubled-backslash", REG, R + r"\\cgi-bin\secret.txt", DENY),
        ("root-forward-slash", REG, R + r"/cgi-bin\secret.txt", DENY),
        ("index-allocation", REG,
         R + r"\cgi-bin::$INDEX_ALLOCATION\secret.txt", DENY),
        ("i30-index-allocation", REG,
         R + r"\cgi-bin:$I30:$INDEX_ALLOCATION\secret.txt", DENY),
        # Existing protections.
        ("canonical-secret", PROT, R + r"\cgi-bin\secret.txt", DENY),
        ("canonical-exe", PROT, R + r"\cgi-bin\loclocal.exe", DENY),
        ("upper-secret", PROT, R.upper() + r"\CGI-BIN\SECRET.TXT", DENY),
        ("doubled-backslash", PROT, R + r"\cgi-bin\\secret.txt", DENY),
        ("trailing-space-dir", PROT, R + "\\cgi-bin \\secret.txt", DENY),
        ("trailing-dot-file", PROT, R + r"\cgi-bin\secret.txt.", DENY),
        ("ads-secret", PROT, R + r"\cgi-bin\secret.txt::$DATA", DENY),
        ("relative", PROT, "page.html", DENY),
        ("drive-relative", PROT, drive + "page.html", DENY),
        ("rooted-no-drive", PROT, rest + r"\page.html", DENY),
        ("extended-prefix", PROT, "\\\\?\\" + R + r"\page.html", DENY),
        ("device-prefix", PROT, "\\\\.\\" + R + r"\page.html", DENY),
        ("unc", PROT, r"\\localhost\tinyweb-no-such-share\page.html", DENY),
        ("rfc-local-redirect", PROT, "/page.html", DENY),
        ("directory", PROT, R + r"\sub", DENY),
        ("exact-root", PROT, R, DENY),
        # A letter outside ASCII that NTFS does not fold onto 'i'.
        ("dotless-i", PROT, R + "\\cg\u0131-bin\\secret.txt", DENY),
        ("other-drive", PROT, other + r"\tinyweb-no-such-dir\page.html", DENY),
        ("outside-absolute", PROT, r"C:\Windows\win.ini", DENY),
        ("missing", PROT, R + r"\no-such-file.html", DENY),
        ("device-con", PROT, R + r"\con", DENY),
        ("device-nul-ext", PROT, R + r"\nul.txt", DENY),
        ("control-byte", PROT, R + "\\page.html\t", DENY),
        ("del-byte", PROT, R + "\\page\x7f.html", DENY),
        ("too-long", PROT, R + "\\" + "a" * 300 + ".html", DENY),
        # Compatibility.
        ("page", COMPAT, R + r"\page.html", serve(PAGE)),
        ("nested", COMPAT, R + r"\sub\index.html", serve(SUB)),
        ("upper-page", COMPAT, R.upper() + r"\PAGE.HTML", serve(PAGE)),
        ("lower-page", COMPAT, R.lower() + r"\page.html", serve(PAGE)),
        ("url", COMPAT, REDIRECT_URL, REDIRECT),
        # Documented changes.
        ("forward-slash-static", CHANGE, R + r"\sub/index.html", DENY),
        ("ads-page", CHANGE, R + r"\page.html::$DATA", DENY),
        ("nul-byte", CHANGE, R + "\\page.html\x00.txt", DENY),
        ("embedded-scheme", CHANGE, "/go?to=http://example.invalid/", DENY),
    ]


LOCATION_IDS = [c[0] for c in location_cases("X:\\R", "R")]


@pytest.mark.parametrize("case_id", LOCATION_IDS)
def test_location_value(box, case_id):
    cases = {c[0]: c for c in location_cases(box.R, box.root.name)}
    _, cls, value, expect = cases[case_id]
    try:
        _encode(value)
    except UnicodeEncodeError:
        pytest.skip("the server's ANSI code page cannot spell this value")
    check(cls, case_id, expect, box.location(value))


# The URI route must also refuse components ending in a dot or a space.
URI_CASES = [
    ("uri-trailing-dot-dir", PROT, "/cgi-bin./secret.txt", DENY),
    ("uri-trailing-dot-exe", PROT, "/cgi-bin./loclocal.exe", DENY),
    ("uri-trailing-space-dir", PROT, "/cgi-bin%20/secret.txt", DENY),
    ("uri-page", COMPAT, "/page.html", serve(PAGE)),
    ("uri-upper-page", COMPAT, "/PAGE.HTML", serve(PAGE)),
    ("uri-nested", COMPAT, "/sub/index.html", serve(SUB)),
    ("uri-directory-index", COMPAT, "/sub/", serve(SUB)),
]


@pytest.mark.parametrize("case_id,cls,target,expect", URI_CASES,
                         ids=[c[0] for c in URI_CASES])
def test_uri(box, case_id, cls, target, expect):
    check(cls, case_id, expect, box.get(target))


def _raw_head(box, target):
    data = box.env.raw(b"HEAD " + target + b" HTTP/1.1\r\nHost: t\r\n"
                       b"Connection: close\r\n\r\n")
    head, _, tail = data.partition(b"\r\n\r\n")
    return head.split(b"\r\n", 1)[0], tail


def test_head_location_file_answers_as_head_static(box):
    # HEAD via Location answers like HEAD on the URI route for the same file.
    loc_status, loc_tail = _raw_head(box, b"/cgi-bin/loclocal.exe?target=page")
    uri_status, uri_tail = _raw_head(box, b"/page.html")
    _record(COMPAT, "head-location-page", "%s/%d bytes" % (
        loc_status[9:12].decode(), len(loc_tail)), loc_tail)
    _record(COMPAT, "head-uri-page", "%s/%d bytes" % (
        uri_status[9:12].decode(), len(uri_tail)), uri_tail)
    assert b" 200 " in loc_status, loc_status
    assert b" 200 " in uri_status, uri_status
    assert loc_tail == uri_tail


# RFC 9110 Section 9.3.2: a HEAD answer carries no content; both routes still
# send the file, so this is a strict expected failure.
@pytest.mark.xfail(strict=True, reason="HEAD sends the file body")
@pytest.mark.parametrize("target", [b"/page.html",
                                    b"/cgi-bin/loclocal.exe?target=page"])
def test_head_sends_no_body(box, target):
    status, tail = _raw_head(box, target)
    assert b" 200 " in status, status
    assert tail == b""


# Separator, suffix, dot-segment, case and prefix variants of each target;
# only canonical spellings and their case changes may serve an allowed file.
CORPUS_TARGETS = [
    (("cgi-bin", "secret.txt"), None),
    (("cgi-bin", "loclocal.exe"), None),
    (("page.html",), PAGE),
    (("sub", "index.html"), SUB),
]


def spellings(R, comps):
    """(tag, value, canonical) for the corpus spellings of R\\comps."""

    def build(parts, seps):
        s = parts[0]
        for sep, part in zip(seps, parts[1:]):
            s += sep + part
        return s

    base = [R] + list(comps)
    std = ["\\"] * len(comps)
    out = [("canonical", build(base, std), True)]
    for i in range(len(comps)):
        for sep, tag in (("/", "slash"), ("\\\\", "double")):
            seps = list(std)
            seps[i] = sep
            out.append(("%s%d" % (tag, i), build(base, seps), False))
    for k in range(1, len(base)):
        for suffix, tag in ((".", "dot"), (" ", "space"), ("::$DATA", "ads"),
                            (":$I30:$INDEX_ALLOCATION", "i30")):
            parts = list(base)
            parts[k] += suffix
            out.append(("%s%d" % (tag, k), build(parts, std), False))
        for insert, tag in ((".", "cur"), ("sub\\..", "up")):
            parts = base[:k] + [insert] + base[k:]
            out.append(("%s%d" % (tag, k),
                        build(parts, ["\\"] * (len(parts) - 1)), False))
    for fold, tag in ((str.upper, "upper"), (str.lower, "lower"),
                      (str.swapcase, "swap")):
        out.append((tag, build([fold(p) for p in base], std), True))
    out.append(("extended", "\\\\?\\" + build(base, std), False))
    out.append(("device", "\\\\.\\" + build(base, std), False))
    return out


def test_location_spelling_corpus(box):
    problems = []
    probes = 0
    for comps, marker in CORPUS_TARGETS:
        for tag, value, canonical in spellings(box.R, comps):
            case_id = "corpus-%s-%s" % ("-".join(comps), tag)
            if marker is not None and canonical:
                expect = serve(marker)
            else:
                expect = DENY
            result = box.location(value)
            _record("corpus", case_id, result[0], result[2])
            probes += 1
            problem = _problem(case_id, expect, result)
            if problem:
                problems.append(problem)
    assert probes >= 80, probes
    assert not problems, "\n".join(problems)


# Filesystem identity: junctions under the web root. Creating one needs no
# administrator rights.
@pytest.fixture(scope="module")
def junctions(box):
    if WINE or sys.platform != "win32":
        pytest.skip("junctions are created through the Windows API")
    import _winapi
    links = {
        "jcgi": box.root / "cgi-bin",
        "jout": box.sibling,
        "jsub": box.root / "sub",
    }
    made = []
    try:
        for name, target in links.items():
            link = box.root / name
            try:
                _winapi.CreateJunction(str(target), str(link))
            except OSError as exc:
                pytest.skip("cannot create a junction here: %s" % exc)
            made.append(link)
        yield box
    finally:
        # os.rmdir removes the junction itself, never its target's content.
        for link in made:
            os.rmdir(link)


def junction_cases(R):
    return [
        ("junction-to-cgi-bin", REG, ("loc", R + r"\jcgi\secret.txt"), DENY),
        ("junction-to-cgi-bin-exe", REG, ("loc", R + r"\jcgi\loclocal.exe"), DENY),
        ("junction-outside-root", REG, ("loc", R + r"\jout\marker.txt"), DENY),
        ("junction-inside-root", COMPAT, ("loc", R + r"\jsub\index.html"),
         serve(SUB)),
        ("uri-junction-to-cgi-bin", REG, ("uri", "/jcgi/secret.txt"), DENY),
        ("uri-junction-outside-root", REG, ("uri", "/jout/marker.txt"), DENY),
        ("uri-junction-inside-root", COMPAT, ("uri", "/jsub/index.html"),
         serve(SUB)),
    ]


JUNCTION_IDS = [c[0] for c in junction_cases("X:\\R")]


@pytest.mark.parametrize("case_id", JUNCTION_IDS)
def test_junction(junctions, case_id):
    box = junctions
    cases = {c[0]: c for c in junction_cases(box.R)}
    _, cls, (route, value), expect = cases[case_id]
    result = box.location(value) if route == "loc" else box.get(value)
    check(cls, case_id, expect, result)


# Symbolic links need SeCreateSymbolicLinkPrivilege or Developer Mode; the
# cases skip where neither is present.
@pytest.fixture(scope="module")
def symlinks(box):
    if WINE or sys.platform != "win32":
        pytest.skip("symbolic links are created through the Windows API")
    links = [
        (box.root / "flink.txt", box.root / "cgi-bin" / "secret.txt", False),
        (box.root / "dlink", box.root / "cgi-bin", True),
        (box.root / "olink.txt", box.sibling / "marker.txt", False),
    ]
    made = []
    try:
        for link, target, is_dir in links:
            try:
                os.symlink(str(target), str(link), target_is_directory=is_dir)
            except OSError as exc:
                pytest.skip("cannot create a symbolic link here: %s" % exc)
            made.append((link, is_dir))
        yield box
    finally:
        for link, is_dir in made:
            if is_dir:
                os.rmdir(link)
            else:
                os.unlink(link)


def symlink_cases(R):
    return [
        ("symlink-file-to-cgi-bin", REG, ("loc", R + r"\flink.txt"), DENY),
        ("symlink-dir-to-cgi-bin", REG, ("loc", R + r"\dlink\secret.txt"), DENY),
        ("symlink-file-outside-root", REG, ("loc", R + r"\olink.txt"), DENY),
        ("uri-symlink-file-to-cgi-bin", REG, ("uri", "/flink.txt"), DENY),
        ("uri-symlink-dir-to-cgi-bin", REG, ("uri", "/dlink/secret.txt"), DENY),
        ("uri-symlink-file-outside-root", REG, ("uri", "/olink.txt"), DENY),
    ]


SYMLINK_IDS = [c[0] for c in symlink_cases("X:\\R")]


@pytest.mark.parametrize("case_id", SYMLINK_IDS)
def test_symlink(symlinks, case_id):
    box = symlinks
    cases = {c[0]: c for c in symlink_cases(box.R)}
    _, cls, (route, value), expect = cases[case_id]
    result = box.location(value) if route == "loc" else box.get(value)
    check(cls, case_id, expect, result)


def _handle_count(pid):
    k32 = ctypes.windll.kernel32
    h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return None
    try:
        n = ctypes.c_ulong()
        if not k32.GetProcessHandleCount(h, ctypes.byref(n)):
            return None
        return n.value
    finally:
        k32.CloseHandle(h)


def test_refusals_keep_the_handle_count(junctions):
    # Each handle-time refusal must close its handle; CGI pipes and threads
    # make the count noisy, hence the slack.
    box = junctions
    values = [
        box.R + r"\jcgi\secret.txt",
        box.R + r"\jout\marker.txt",
        box.R + r"\cgi-bin.\secret.txt",
        box.R + r"\sub\..\cgi-bin\secret.txt",
    ]
    for _ in range(3):
        box.location(box.R + r"\page.html")
    before = _handle_count(box.env.proc.pid)
    if before is None:
        pytest.skip("the server's handle count cannot be read")
    for _ in range(25):
        for value in values:
            status, headers, body = box.location(value)
            assert not disclosed(body) and status == 403, status
    after = _handle_count(box.env.proc.pid)
    _record("resource", "handle-count-before-after", "%s/%s" % (before, after), b"")
    assert after - before < 20, (before, after)


def test_server_answers_after_refusals(box):
    check(COMPAT, "after-refusals-page", serve(PAGE), box.get("/page.html"))
    check(COMPAT, "after-refusals-location-page", serve(PAGE),
          box.location(box.R + r"\page.html"))
