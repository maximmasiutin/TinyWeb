//////////////////////////////////////////////////////////////////////////
//
//  CGI Testing Example
//
//  Copyright (C) 1997 RIT Research Labs
//
//////////////////////////////////////////////////////////////////////////
//
//  SECURITY WARNING - DEMONSTRATION CODE ONLY
//  ===========================================
//  This file contains HARDCODED CREDENTIALS for demonstration purposes.
//  DO NOT use hardcoded passwords in production applications.
//
//  In production systems:
//  - Store password hashes, not plaintext passwords
//  - Use secure password hashing (bcrypt, Argon2, PBKDF2)
//  - Implement proper authentication mechanisms
//  - Use environment variables or secure vaults for secrets
//
//  The credentials in this demo (Jimmi/Hendrix) are intentionally
//  obvious to demonstrate CGI functionality, not secure authentication.
//
//////////////////////////////////////////////////////////////////////////



unit LoginU;

interface

procedure ComeOn;


implementation

uses
  Windows,
  SysUtils;


var
    StdIn,
    StdOut: Integer;

    UserName: String;
    UserPsw: String;

procedure OutWriteLn(const S: String);
 var SS: String;
     DW: DWord;
begin
  SS := S+#13#10;
  WriteFile(StdOut, SS[1], Length(SS), DW, nil);
end;


procedure ShowError(const ErrorStr: String);
var
  S: string;
begin
  S := 'Error: '+ErrorStr;

  OutWriteLn('Content-Type: text/html');
  OutWriteLn('');
  OutWriteLn('<HTML>');
  OutWriteLn('<HEAD>');
  OutWriteLn('<TITLE>Error</TITLE>');
  OutWriteLn('</HEAD>');
  OutWriteLn('<BODY>');
  OutWriteLn('');
  OutWriteLn('<H1>'+ ErrorStr+ '</H1>');
  OutWriteLn('<H2>Press BACK button on your browser and fill the form properly');
  OutWriteLn('');
  OutWriteLn('</BODY>');
  OutWriteLn('</HTML>');

  Halt;
end;



procedure DecodeParams(S: string);
  var I,J: Integer;

  procedure Decode(const S: String);
    var A, K: ShortString;
        I,J: Integer;
  begin
    A := '';
    I := 1; J := 0;
    while (J < 255) and (I <= Length(S)) do
     begin
       Inc(J);
       case S[I] of
         '%': begin
                A[J] := Char(StrToInt('$'+Copy(S, I+1, 2)));
                Inc(I, 3);
              end;
         '+': begin A[J] := ' '; Inc(I) end;
            else begin A[J] := S[I]; Inc(I) end;
       end;
     end;
    A[0] := Char(J);
    I := Pos('=', A);
    if I > 0 then
      begin
        K := UpperCase(Copy(A, 1, I-1));
        if K = 'USERID' then UserName := Copy(A, I+1, Length(A)) else
        if K = 'PASSWORD' then UserPsw := Copy(A, I+1, Length(A)) else
        ShowError(Format('Invalid field "%s"', [K]));
      end;
  end;


begin
  UserName := '';
  UserPsw := '';
  I := 1;
  while (I <= Length(S)) do
    begin
      J := 1;
      while (I+J <= Length(S)) and (S[I+J] <> '&') do Inc(J);
      Decode(Copy(S, I, J));
      Inc(I, J+1);
    end;
end;

procedure UserOK;
var
  S: string;
begin
  S := 'OK: '+UserName;

  OutWriteLn('Content-Type: text/html');
  OutWriteLn('');
  OutWriteLn('<HTML>');
  OutWriteLn('<HEAD>');
  OutWriteLn('<TITLE>You were successfully logged in!</TITLE>');
  OutWriteLn('</HEAD>');
  OutWriteLn('<BODY>');
  OutWriteLn('');
  OutWriteLn('<H1>Congratulations, '+UserName+'!</H1>');
  OutWriteLn('<H2>You were successfully logged in!</H2>');
  OutWriteLn('<H2>It means nothing except TinyWeb CGI does work!</H2>');
  OutWriteLn('');
  OutWriteLn('</BODY>');
  OutWriteLn('</HTML>');

  Halt;
end;



procedure ComeOn;
var
  I, J: Integer;
  S: string;

// It was unable to retrieve the posted information
// because the seek to the end of the standard input file always returns zero
// on Windows 95/98 system. Thanks to David Gommeren for fixing that.


  Variable:string;
  Buffer:array [0..4095] of char;
begin
  StdIn  := GetStdHandle(STD_INPUT_HANDLE);
  StdOut := GetStdHandle(STD_OUTPUT_HANDLE);
  S := '';
  SetString(Variable, Buffer, GetEnvironmentVariable(PChar('CONTENT_LENGTH'), Buffer, SizeOf(Buffer)));
  I := StrToInt(Variable);
  if I <= 0 then ShowError('Internal script error reading StdIn');
  FileSeek(StdIn, 0, FILE_BEGIN);
  SetString(S, nil, I);
  FileRead(StdIn, S[1], I);
  DecodeParams(S);
  if UserName = '' then ShowError('User ID field is blank');
  if UserPsw  = '' then ShowError('Password field is blank');
  if UserName <> 'Jimmi' then ShowError(Format('User %s is not allowed to log in', [UserName]));
  if UserPsw <> 'Hendrix' then ShowError(Format('Invalid password for user %s', [UserName]));
  UserOK;
end;

end.

