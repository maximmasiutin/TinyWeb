// CGI fixture: answers a Location holding an absolute filesystem path, picked by
// QUERY_STRING target=page, self (also empty) or secret; other values get 400.
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
