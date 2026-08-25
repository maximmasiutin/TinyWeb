// CGI test fixture: dumps the CGI environment and command line.
// Deliberately sends NO Content-Length header: RFC 3875 Section 6.3 makes
// it optional, and TinyWeb 2.03-2.05 returned 500 for every such response
// (the DoCollect _Val regression), so this fixture is the canary for that.
program envdump;
{$MODE OBJFPC}
uses
  SysUtils;
var
  i: Integer;
begin
  WriteLn('Content-type: text/plain');
  WriteLn;
  WriteLn('envdump-marker');
  WriteLn('REQUEST_METHOD=', GetEnvironmentVariable('REQUEST_METHOD'));
  WriteLn('QUERY_STRING=', GetEnvironmentVariable('QUERY_STRING'));
  WriteLn('SCRIPT_NAME=', GetEnvironmentVariable('SCRIPT_NAME'));
  WriteLn('PATH_INFO=', GetEnvironmentVariable('PATH_INFO'));
  WriteLn('GATEWAY_INTERFACE=', GetEnvironmentVariable('GATEWAY_INTERFACE'));
  WriteLn('SERVER_PROTOCOL=', GetEnvironmentVariable('SERVER_PROTOCOL'));
  WriteLn('CONTENT_LENGTH=', GetEnvironmentVariable('CONTENT_LENGTH'));
  WriteLn('CONTENT_TYPE=', GetEnvironmentVariable('CONTENT_TYPE'));
  WriteLn('HTTP_USER_AGENT=', GetEnvironmentVariable('HTTP_USER_AGENT'));
  WriteLn('HTTP_COOKIE=', GetEnvironmentVariable('HTTP_COOKIE'));
  WriteLn('ARGC=', ParamCount);
  for i := 1 to ParamCount do
    WriteLn('ARGV', i, '=', ParamStr(i));
end.
