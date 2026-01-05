{  Dos CGI Testing Example provided by Martin Lafferty}

{  Should be compiled by Borland/Turbo Pascal compiler for DOS }

{  SECURITY WARNING - DEMONSTRATION CODE ONLY                    }
{  ===========================================                    }
{  This file contains HARDCODED CREDENTIALS for demonstration.   }
{  DO NOT use hardcoded passwords in production applications.    }
{                                                                 }
{  In production systems:                                         }
{  - Store password hashes, not plaintext passwords               }
{  - Use secure password hashing (bcrypt, Argon2, PBKDF2)         }
{  - Implement proper authentication mechanisms                   }
{  - Use environment variables or secure vaults for secrets       }
{                                                                 }
{  The credentials in this demo (Jimmi/Hendrix) are intentionally }
{  obvious to demonstrate CGI functionality, not secure auth.     }

program Doscgi;
uses
  Strings,
  Dos;

var
  UserName: String;
  UserPsw: String;


procedure ShowError(const ErrorStr: String);
var
  S: string;
begin
  S := 'Error: '+ErrorStr;

  Writeln(Output, 'Content-Type: text/html');
  Writeln(Output, '');
  Writeln(Output, '<HTML>');
  Writeln(Output, '<HEAD>');
  Writeln(Output, '<TITLE>Error</TITLE>');
  Writeln(Output, '</HEAD>');
  Writeln(Output, '<BODY>');
  Writeln(Output, '');
  Writeln(Output, '<H1>'+ ErrorStr+ '</H1>');
  Writeln(Output, '<H2>Press BACK button on your browser and fill the form properly');
  Writeln(Output, '');
  Writeln(Output, '</BODY>');
  Writeln(Output, '</HTML>');

  Halt;
end;


function StrToInt(const S: String): Integer;
var
  Result, c : Integer;
begin
  Val(S, Result, C);
  if C <> 0 then Result:= 0;
  StrToInt:= Result
end;


function UpperCase( const S: String): String;
var
  Result: String;
  i: Integer;
begin
  Result:= S;
  for i:= 1 to Length(Result) do
    Result[i]:= UpCase(Result[i]);
  UpperCase:= Result
end;

procedure DecodeParams(P: PChar);
  var J: PChar;

  procedure Decode(const S: String);
    var A, K: String;
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
        ShowError('Invalid field ' + K);
      end;
  end;


begin
  UserName := '';
  UserPsw := '';
  repeat
    J:= P;
    while (J^ <> #0) and (J^ <> '&') do
      Inc(J);
    if J^ <> #0 then
    begin
      J^:= #0;
      Decode(StrPas(P));
      P:= J + 1
    end else
    begin
      Break
    end
  until false;
  Decode(StrPas(P));
end;

procedure UserOK;
var
  S: string;
begin
  S := 'OK: '+UserName;

  Writeln(Output, 'Content-Type: text/html');
  Writeln(Output, '');
  Writeln(Output, '<HTML>');
  Writeln(Output, '<HEAD>');
  Writeln(Output, '<TITLE>You were successfully logged in!</TITLE>');
  Writeln(Output, '</HEAD>');
  Writeln(Output, '<BODY>');
  Writeln(Output, '');
  Writeln(Output, '<H1>Congratulations, '+UserName+'!</H1>');
  Writeln(Output, '<H2>You were successfully logged in!</H2>');
  Writeln(Output, '<H2>It means nothing except TinyWeb CGI does work!</H2>');
  Writeln(Output, '');
  Writeln(Output, '</BODY>');
  Writeln(Output, '</HTML>');

  Halt;
end;



procedure ComeOn;
var
  S: String;
  I, J: Integer;
  Variable:string;
  Buffer:array [0..4095] of char;
begin
  Variable:= GetEnv('CONTENT_LENGTH');
  I := StrToInt(Variable);
  if (I <= 0) or (I >= sizeof(Buffer)) then ShowError('Internal script error reading StdIn');
  for j:= 0 to I - 1 do
    Read(Input, Buffer[j]); {slow}
  Buffer[I]:= #0;
  DecodeParams(Buffer);
  if UserName = '' then ShowError('User ID field is blank');
  if UserPsw  = '' then ShowError('Password field is blank');
  if UserName <> 'Jimmi' then ShowError('User ' + UserName + 'is not allowed to log in');
  if UserPsw <> 'Hendrix' then ShowError('Invalid password for user ' + UserName);
  UserOK;
end;

begin
  ComeOn
end.

