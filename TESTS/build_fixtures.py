"""Build the test CGI fixtures and the webroot binary set.

Used two ways:
- imported by conftest.py, which calls build_all() before the server starts;
- run directly (python TESTS/build_fixtures.py) on a Windows host to
  pre-build _work/bin for the Wine container lane, where no compiler runs.

Compilers:
- FPC builds every Pascal fixture (TESTS/cgi/*.pas) and the CGITEST Delphi
  example (login.dpr, -MDelphi). FPC location: the FPC environment variable,
  then fpc on PATH.
- gcc, when present, builds the CGITEST C examples (hello.c, helloh.c).
  Their absence only skips the corresponding tests.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO = TESTS_DIR.parent
CGI_SRC = TESTS_DIR / "cgi"
CGITEST = REPO / "CGITEST"
# Not ".work": Wine presents dot-directories as hidden, and TinyWeb
# refuses to serve from a directory carrying the hidden attribute.
WORK = TESTS_DIR / "_work"
BIN = WORK / "bin"

PASCAL_FIXTURES = [
    "envdump.pas",
    "postecho.pas",
    "clenresp.pas",
    "statusdir.pas",
    "locdir.pas",
    "dupclen.pas",
    "badclen.pas",
    "emptyclen.pas",
]

C_FIXTURES = ["hello.c", "helloh.c"]


def find_fpc():
    exe = os.environ.get("FPC")
    if exe and Path(exe).is_file():
        return exe
    return shutil.which("fpc")


def find_gcc():
    return shutil.which("gcc")


def _run(cmd, cwd=None):
    proc = subprocess.run(
        cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "command failed (%d): %s\n%s" % (proc.returncode, " ".join(map(str, cmd)), proc.stdout)
        )


def build_all():
    """Compile every buildable fixture into BIN; return a capability dict."""
    BIN.mkdir(parents=True, exist_ok=True)
    caps = {"gcc": False, "login": False}

    fpc = find_fpc()
    if fpc is None:
        raise RuntimeError(
            "FPC not found: set the FPC environment variable, or put fpc on PATH"
        )

    unit_dir = BIN / "units"
    unit_dir.mkdir(exist_ok=True)
    for src in PASCAL_FIXTURES:
        _run([
            fpc, "-B", "-MObjFPC", "-FE" + str(BIN), "-FU" + str(unit_dir),
            str(CGI_SRC / src),
        ])

    try:
        _run([
            fpc, "-B", "-MDelphi", "-FE" + str(BIN), "-FU" + str(unit_dir),
            "-Fu" + str(REPO / "SRC"),  # loginu.pas uses xBase.GetEnvVariable
            str(CGITEST / "login.dpr"),
        ], cwd=CGITEST)
        caps["login"] = True
    except RuntimeError as exc:
        sys.stderr.write("login.dpr fixture skipped: %s\n" % exc)

    gcc = find_gcc()
    if gcc:
        try:
            for src in C_FIXTURES:
                out = BIN / (Path(src).stem + ".exe")
                _run([gcc, str(CGITEST / src), "-o", str(out)])
            caps["gcc"] = True
        except RuntimeError as exc:
            sys.stderr.write("C fixtures skipped: %s\n" % exc)

    return caps


if __name__ == "__main__":
    built = build_all()
    print("fixtures built into", BIN)
    print("capabilities:", built)
