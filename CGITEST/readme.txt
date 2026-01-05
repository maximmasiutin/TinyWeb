CGITEST - CGI Testing Examples for TinyWeb
===========================================

SECURITY WARNING
----------------
These files are DEMONSTRATION CODE ONLY. They contain hardcoded
credentials (Jimmi/Hendrix) for testing CGI functionality.

DO NOT use these examples as templates for production authentication:
- Never hardcode passwords in source code
- Use secure password hashing (bcrypt, Argon2, PBKDF2)
- Store credentials in secure vaults or environment variables
- Implement proper session management and CSRF protection

Files are provided here to test CGI.

hello.c  - Displays "Hello, world" in plain form. Compile hello.c into
           hello.exe, place the .exe to /cgi-bin/ and request 
           /cgi-bin/hello.exe

helloh.c - Displays "Hello, world!" in html form. The instructions are the
           same as for hello.c - just compile helloh.c into helloh.exe, 
	   place the .exe to /cgi-bin/ and request /cgi-bin/helloh.exe

hello.pl - Displays "Hello, World!" in plain form. Requires Perl installed.
           Just place hello.pl to /cgi-bin/ and request /cgi-bin/hello.pl


login.htm, login.c, login.dpr, and loginu.pas give an example of processing
CGI arguments from applications written in C or Delphi.



 