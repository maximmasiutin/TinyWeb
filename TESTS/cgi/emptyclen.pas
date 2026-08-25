// CGI test fixture: a response with a PRESENT but EMPTY Content-Length
// value must be rejected by the server (surfacing as 500); only a truly
// absent header may fall back to the body-derived length.
program emptyclen;
begin
  WriteLn('Content-type: text/plain');
  WriteLn('Content-length:');
  WriteLn;
  WriteLn('emptyclen-marker');
end.
