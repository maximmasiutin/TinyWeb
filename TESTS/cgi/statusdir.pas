// CGI test fixture: the Status directive (RFC 3875 Section 6.3.3) must set
// the HTTP status code of the response.
program statusdir;
begin
  WriteLn('Status: 404 Not Found');
  WriteLn('Content-type: text/plain');
  WriteLn;
  WriteLn('statusdir-marker');
end.
