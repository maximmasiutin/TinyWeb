# TinyWeb Server
Version 1.99
Released January 5, 2026  
Written by Maxim Masiutin  
Copyright (C) 2021-2026 Maxim Masiutin  
Copyright (C) 2000-2017 RITLABS S.R.L.  
Copyright (C) 1997-2000 RIT Research Labs  

## Setup
To set up the TinyWeb Server, just create a shortcut in the Startup menu with the following properties:

### Target
`c:\www\bin\tiny.exe c:\www\root`
### Start In
`c:\www\log`


Here, `c:\www\bin\tiny.exe` is the path to TinyWeb executable, `c:\www\root` is the path to www home (root) directory, and `c:\www\log` is the directory for log files that TinyWeb keeps.

**Note:** These paths are just examples. You can customize them to your needs. Also, make sure that an `index.html` file exists in your www home (root) directory, otherwise the server will fail to start.

TinyWeb is not a windowed application, so there is no window with TinyWeb. It is also not a console application, so there is no console window for TinyWeb. Moreover, it is not a Windows Service. Once started, the `tiny.exe` process will appear in Task List. There is no way to stop Tiny Web except via the "End Task" operation.

## Command-line Options
1. First parameter (mandatory) is a path to the www home (root) directory.
2. Second parameter (optional) is a port number. By default, it is 80 for HTTP and 443 for HTTPS(SSL/TLS).
3. Third parameter (optional) is a dotted-decimal IP address to bind the server. By default, TinyWeb binds to all available local addresses.

## Examples

### Run TinyWeb on port 8000:
`c:\www\bin\tiny.exe c:\www\root 8000`
### Run TinyWeb on port 8000 and address 212.56.194.250:
`c:\www\bin\tiny.exe c:\www\root 8000 212.56.194.250`

## Building CGI Executables with Docker

The Docker container is provided to cross-compile CGI test programs from C source code into Windows executables without requiring MinGW installation on your Windows system. This is particularly useful for:
- Testing CGI functionality without setting up a C compiler
- Building Windows executables on Linux/Mac systems
- Ensuring consistent build environments

### Docker Files

- **Dockerfile** - Uses `debian:stable-slim` with `mingw-w64` to cross-compile `CGITEST/login.c` into a 64-bit Windows executable (`login.exe`)
- **.dockerignore** - Excludes build artifacts, logs, and documentation from Docker context

### Build the Docker Image
```cmd
docker build -t tinyweb-builder .
```

### Extract the Compiled Executable
```cmd
docker create --name temp-builder tinyweb-builder
docker cp temp-builder:/home/builder/app/login.exe ./login.exe
docker rm temp-builder
```

The compiled `login.exe` can then be copied to your TinyWeb CGI directory (e.g., `c:\www\root\cgi-bin\`).

To build other CGI examples from `CGITEST/` (e.g., `hello.c`), modify the `COPY` and `RUN` lines in the Dockerfile.

## CGI Query Parameter Handling

TinyWeb supports ISINDEX-style queries per [RFC 3875 Section 4.4](https://datatracker.ietf.org/doc/html/rfc3875#section-4.4). Query strings without `=` are passed as command-line arguments to CGI scripts.

### Security

CGI query parameters are protected by two layers:
1. **Whitelist validation** (optional): Rejects parameters with unsafe characters
2. **Apache-style escaping** (always active): Escapes shell metacharacters

### Configuration

The `STRICT_CGI_PARAMS` define in `SRC/define.inc` controls whitelist validation:
- **Enabled (default)**: Only allows `[A-Za-z0-9._-/\:]` in query parameters
- **Disabled**: Allows all characters (escaped for safety)

To disable strict mode, comment out `{$DEFINE STRICT_CGI_PARAMS}` in `define.inc`.

## Security Vulnerabilities Fixed

TinyWeb has addressed the following CVEs:

| CVE | Type | Severity | Fixed In |
|-----|------|----------|----------|
| CVE-2024-5193 | CRLF Injection (CWE-93) | Medium (5.3) | v1.99 |
| CVE-2024-34199 | Buffer Overflow (CWE-787) | High (8.6) | v1.99 |
| CVE Request 1971570 | Command Injection (CWE-78) | Critical (9.8) | v1.98 |
| CVE-2004-2636 | Path Traversal (CWE-22) | High | v1.93+ |
| CVE-2003-1510 | Denial of Service | High (7.8) | v1.93+ |

**Recommendation:** Always use the latest version of TinyWeb.
