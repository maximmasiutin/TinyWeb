FROM debian:stable-slim

RUN apt-get update && apt-get install -y --no-install-recommends fpc python3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m builder
USER builder

WORKDIR /home/builder/app
COPY --chown=builder:builder --chmod=444 . ./

RUN fpc -B -MObjFPC -Tlinux -Px86_64 -O4 SRC/Tiny.dpr

# Run the python test on build
RUN python3 TESTS/test_server.py

HEALTHCHECK CMD test -f /home/builder/app/SRC/Tiny