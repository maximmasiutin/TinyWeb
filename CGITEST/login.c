//////////////////////////////////////////////////////////////////////////
//
//  CGI Testing Example
//
//  Copyright (C) 1997 RIT Research Labs
//
//////////////////////////////////////////////////////////////////////////



#include <stdio.h>
#include <windows.h>

void main(void)
{

  HANDLE StdIn;
  int Size;
  DWORD Actual;
  char* String;


  StdIn = GetStdHandle(STD_INPUT_HANDLE);

///////////////////

  Size = SetFilePointer(StdIn, 0, NULL, FILE_END);
  SetFilePointer(StdIn, 0, NULL, FILE_BEGIN);

///////////////////
//
// Note that getting size of data available in StdIn via SetFilePointer()
// works under WinNT only. Under Win9x, you should get the size from
// CONTENT_LENGTH environment variable.
//
///////////////////


  String = malloc(Size+1);
  if (Size <= 0) return;

  ReadFile(StdIn, String, Size, &Actual, NULL);

  String[Size] = 0;

  printf("Content-Type: text/plain\n\n");

  printf("%s\n\n", String);

  printf("This means nothing except TinyWeb CGI works\n");

}
