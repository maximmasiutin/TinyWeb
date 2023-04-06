# TinyWeb Server 
Version 1.96  
Released August 8, 2021  
Written by Maxim Masiutin  
Copyright (C) 2021-2023 Maxim Masiutin  
Copyright (C) 2000-2017 RITLABS S.R.L.  
Copyright (C) 1997-2000 RIT Research Labs  

## Setup
To set up the TinyWeb Server, just create a shortcut in the Startup menu with the following properties:

### Target
`c:\www\bin\tiny.exe c:\www\root`
### Start In
`c:\www\log`


Here, `c:\www\bin\tiny.exe` is the path to TinyWeb executable, `c:\www\root` is the path to www home (root) directory, and `c:\www\log` is the directory for log files that TinyWeb keeps.

TinyWeb is not a windowed application, so there is no window with TinyWeb. It is also not a console application, so there is no console window for TinyWeb. Moreover, it is not a Windows Service. Once started, the `tiny.exe` process will appear in Task List. There is no way to stop Tiny Web except via the „End Task” operation.

## Command-line Options
1. First parameter (mandatory) is a path www home (root) directory.
2. Second parameter (optional) is a port number. By default, it is 80 for HTTP and 443 for HTTPS(SSL/TLS).
3. Third parameter (optional) is a dotted-decimal IP address to bind the server. By default, TinyWeb binds to all available local addresses.

## Examples

### Run TinyWeb on port 8000:
`c:\www\bin\tiny.exe c:\www\root 8000`
### Run TinyWeb on port 8000 and address 212.56.194.250:
`c:\www\bin\tiny.exe c:\www\root 8000 212.56.194.250`
