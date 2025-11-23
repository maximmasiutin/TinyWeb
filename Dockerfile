FROM debian:stable-slim
RUN apt-get update && apt-get install -y mingw-w64 && rm -rf /var/lib/apt/lists/*
COPY CGITEST/login.c /app/login.c
WORKDIR /app
RUN x86_64-w64-mingw32-gcc -o login.exe login.c