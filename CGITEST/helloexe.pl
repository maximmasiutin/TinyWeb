##########################################################################
##
##  CGI Testing Example
##
##  Copyright (C) 1998-2000 RIT Research Labs
##
##  This is a sample 'Hello World' program, where 'Hello' is printed
##  from a perl script and 'World' is printed from an executable written in
##  C and invoked from the perl script.
##
##########################################################################

print "Content-Type: text/html\n\n";

print "Hello ";

print `world.exe`;




