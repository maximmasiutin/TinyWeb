// CGI test fixture: reads CONTENT_LENGTH bytes from standard input and
// echoes them back, prefixed with the byte count. Sends no Content-Length
// in the response on purpose (see envdump.pas).
program postecho;
{$MODE OBJFPC}
uses
  SysUtils, Windows;
var
  n, total, got: Integer;
  buf: array[0..8191] of AnsiChar;
  body: AnsiString;
  h: THandle;
begin
  n := StrToIntDef(SysUtils.GetEnvironmentVariable('CONTENT_LENGTH'), 0);
  body := '';
  total := 0;
  h := GetStdHandle(STD_INPUT_HANDLE);
  while total < n do
  begin
    got := FileRead(h, buf, SizeOf(buf));
    if got <= 0 then
      Break;
    SetLength(body, total + got);
    Move(buf, body[total + 1], got);
    Inc(total, got);
  end;
  WriteLn('Content-type: application/octet-stream');
  WriteLn;
  WriteLn('postecho-bytes=', total);
  Write(body);
end.
