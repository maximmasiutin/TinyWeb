// CGI test fixture: a response carrying TWO Content-Length headers must be
// rejected by the server (RFC 9110 Section 8.6), surfacing as 500.
program dupclen;
begin
  WriteLn('Content-type: text/plain');
  WriteLn('Content-length: 5');
  WriteLn('Content-length: 7');
  WriteLn;
  WriteLn('dupclen-marker');
end.
