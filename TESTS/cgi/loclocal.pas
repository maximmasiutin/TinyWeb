// CGI fixture: answers a Location holding an absolute filesystem path, picked by
// target=page, self (also empty), secret, or file (cgi-bin\loclocal.txt); else 400.
program loclocal;
{$H+}
uses
  SysUtils;

function ReadTargetFile(const Name: string): string;
var
  F: File;
  n: LongInt;
begin
  Result := '';
  FileMode := 0;
  AssignFile(F, Name);
  {$I-}
  Reset(F, 1);
  {$I+}
  if IOResult <> 0 then
    Exit;
  n := FileSize(F);
  SetLength(Result, n);
  if n > 0 then
    BlockRead(F, Result[1], n);
  CloseFile(F);
end;

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
  else if Query = 'target=file' then
    Target := ReadTargetFile(CgiDir + 'loclocal.txt')
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
