//////////////////////////////////////////////////////////////////////////
//
//  CGI Testing Example
//
//  Copyright (C) 1997 RIT Research Labs
//
//////////////////////////////////////////////////////////////////////////

#include <stdio.h>

void main(void)
{
  printf("Content-Type: text/html\n\n");

  printf("<HTML>\n");
  printf("<HEAD>\n");
  printf("<TITLE>Hello</TITLE>\n");
  printf("</HEAD>\n");
  printf("<BODY>\n");
  printf("<CENTER><HR>\n");
  printf("<H1>Hello, world!</H1>\n");
  printf("<H2>Hello, world!</H2>\n");
  printf("<H3>Hello, world!</H3>\n");
  printf("<H4>Hello, world!</H4>\n");
  printf("<H5>Hello, world!</H5>\n");
  printf("<HR></CENTER>\n");
  printf("</BODY>\n");
  printf("</HTML>\n");
}