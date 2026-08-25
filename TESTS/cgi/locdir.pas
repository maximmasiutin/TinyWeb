// CGI test fixture: the Location directive with an absolute URL
// (RFC 3875 Section 6.3.2); TinyWeb answers 302 with that Location.
program locdir;
begin
  WriteLn('Location: http://example.invalid/moved');
  WriteLn;
end.
