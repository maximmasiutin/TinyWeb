# Wine-based container lane for the TinyWeb test suite.
#
# The server is a Win32 binary, so a Linux container runs it through Wine.
# Nothing is compiled in here: build the server and the fixtures on a
# Windows host first (TESTS/run_container.ps1 does all three steps), then
# the suite runs with the repository mounted:
#
#   docker build -t tinyweb-tests -f TESTS/Dockerfile TESTS
#   docker run --rm -v "${PWD}:/work" -w /work -e TINYWEB_WINE=1 \
#       tinyweb-tests python3 -m pytest TESTS -m "not slow"

FROM debian:stable-slim

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       wine wine32:i386 python3 python3-pytest \
    && rm -rf /var/lib/apt/lists/*

ENV WINEDEBUG=-all
ENV TINYWEB_WINE=1

CMD ["python3", "-m", "pytest", "TESTS", "-m", "not slow"]
