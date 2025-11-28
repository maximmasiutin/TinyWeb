FROM debian:stable-slim

RUN apt-get update && apt-get install -y --no-install-recommends mingw-w64 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m builder
USER builder

WORKDIR /home/builder/app
COPY --chown=builder:builder --chmod=444 CGITEST/login.c ./login.c

RUN x86_64-w64-mingw32-gcc -o login.exe login.c

HEALTHCHECK CMD test -f /home/builder/app/login.exe