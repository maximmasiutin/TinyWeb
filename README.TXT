    TinyWeb 0.3 (22-Oct-1997)
    Copyright (C) 1997 RIT Research Labs
    All Rights Reserved.


TinyWeb is intended to be a simple web server for Win32, written by
Max Masyutin (max@ritlabs.com).

Homepage:
    http://www.ritlabs.com/tinyweb/  

The current version of this program is available at
    http://www.ritlabs.com/ftp/pub/tinyweb/tinyweb.zip
    ftp://ftp.ritlabs.com/pub/tinyweb/tinyweb.zip


This programs is FREE for commercial and non-commercial usage.  
The only restriction is that copyright holder must be attributed 
with the development of this code. See the LICENCE file for more details.  

This program may be freely distributed, provided the distribution package is 
not modified. No person or company may charge a fee for the distribution of 
this program without written permission of the copyright holder.

TinyWeb is extremely small (less than 40K), simple (no any configuration
except command line) and fast (consumes as little system memory and CPU
resources as possible).


                           INSTALLING 


To install TinyWeb server just create an object in Startup folder with the
following properties:

Target     : c:\www\bin\tinyweb.exe c:\www\root
Start In   : c:\www\log

c:\www\bin\tinyweb.exe is a path to TinyWeb executable, c:\www\root is a path
to www home (root) directory, and c:\www\log is a directory for log files
TinyWeb keeps.


                        WHAT DOES TinyWeb DO?


1. Handles http-requests!
-------------------------

Path to home directory is taken from command line as a first and the only
parameter. The default directory root file name is index.html. Make sure that
index.html exists in a directory first command line parameter points to.
Please refer to error_log on any troubles.


2. Executes CGI applications!
----------------------------

The following environment variables are passed to application:

CONTENT_LENGTH
CONTENT_TYPE
GATEWAY_INTERFACE
QUERY_STRING
REMOTE_ADDR
REMOTE_HOST
REQUEST_METHOD
SCRIPT_NAME
SERVER_NAME
SERVER_PORT
SERVER_PROTOCOL
SERVER_SOFTWARE

CGI interface was tested with Perl5 for NT.

CGI application are being executed from /cgi-bin/ directory only.

The samples to test CGI are provided in cgitest.zip package.

Note that TinyWeb extracts content-types, associated to file extensions,
and script interpreters (e.g. Perl) form Windows Registry, so make sure 
that .html, .htm, .cgi, .pl are registered file types. It means that 
I recommend to use .pl as an extension for CGI-scripts written in Perl.


3. Keeps logs!
--------------

TinyWeb keeps Apache-compatible log files access_log, agent_log, referer_log
and error_log, which can be analyzed by any compatible log analyzer, eg:

 - Analog (http://www.statslab.cam.ac.uk/~sret1/analog/)
 - WWWstat (http://www.ics.uci.edu/WebSoft/wwwstat/)
 - wusage (http://siva.cshl.org/wusage.html)
 - WebReport (ftp://ftp.ncsa.uiuc.edu/Mosaic/)

Logs are keeps in a directory from that TinyWeb was started. Make sure that
"Start In" directory of TinyWeb properties is set properly.



Sincerely yours,

  Max Masyutin (max@ritlabs.com)

