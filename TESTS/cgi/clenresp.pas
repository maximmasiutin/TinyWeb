// CGI test fixture: response WITH an explicit Content-Length header,
// the control case beside envdump.pas.
program clenresp;
{$MODE OBJFPC}
var
  Body: AnsiString;
begin
  Body := 'clenresp-marker' + #13#10;
  WriteLn('Content-type: text/plain');
  WriteLn('Content-length: ', Length(Body));
  WriteLn;
  Write(Body);
end.
