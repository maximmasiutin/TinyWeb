# TinyWeb Server 
Version 1.97  
Released April 11, 2023  
Written by Maxim Masiutin  
Copyright (C) 2021-2025 Maxim Masiutin  
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

You can use Docker to cross-compile C files into Windows executables using MinGW.

### Build hello.exe
```cmd
docker build -t tinyweb-login-c .
```

### Extract the executable and copy to cgi-bin
```cmd
docker create --name temp tinyweb-login-c
docker cp temp:/app/hello.exe c:\www\root\cgi-bin\hello.exe
docker rm temp
```

The Dockerfile uses `debian:stable-slim` with MinGW to compile `CGITEST/hello.c` into a Windows executable.

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
