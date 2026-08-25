// CGI test fixture: a response with a malformed Content-Length value must
// be rejected by the server, surfacing as 500. Only a PRESENT malformed
// value is rejected; an absent header is legal (see envdump.pas).
program badclen;
begin
  WriteLn('Content-type: text/plain');
  WriteLn('Content-length: abc');
  WriteLn;
  WriteLn('badclen-marker');
end.
