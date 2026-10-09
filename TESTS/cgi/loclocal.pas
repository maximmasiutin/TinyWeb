// CGI test fixture: a Location header carrying an absolute Windows
// filesystem path, such as C:\www\page.html. This is a TinyWeb extension:
// the server sends the named file itself through OpenRequestedFile. It is
// not the RFC 3875 Section 6.2.2 local redirect, which carries a URL path
// (/page.html) for the server to process as a new request; TinyWeb does
// not implement that form.
//
// QUERY_STRING picks one target from a fixed list; no caller-supplied
// path is ever echoed:
//   target=page   <webroot>\page.html            static file, served (200)
//   target=self   this executable                under cgi-bin, refused (403)
//   target=secret <webroot>\cgi-bin\secret.txt   under cgi-bin, refused (403)
// An empty query string means target=self. Any other value gets a plain
// 400 CGI response with no Location.
program loclocal;
{$H+}
uses
  SysUtils;
var
  Query, CgiDir, WebRoot, Target: string;
begin
  Query := GetEnvironmentVariable('QUERY_STRING');
  CgiDir := ExtractFilePath(ParamStr(0));
  WebRoot := ExtractFilePath(ExcludeTrailingPathDelimiter(CgiDir));
  if (Query = '') or (Query = 'target=self') then
    Target := ParamStr(0)
  else if Query = 'target=page' then
    Target := WebRoot + 'page.html'
  else if Query = 'target=secret' then
    Target := CgiDir + 'secret.txt'
  else
    Target := '';
  if Target = '' then
  begin
    WriteLn('Status: 400 Bad Request');
    WriteLn('Content-Type: text/plain');
    WriteLn;
    WriteLn('loclocal: unknown target');
  end
  else
  begin
    WriteLn('Location: ' + Target);
    WriteLn;
  end;
end.
