// Unit tests for the pure parsing and escaping helpers of SRC/SrvMain.pas,
// reached through the declarations the unit exposes in its interface section.
// Table-driven cases cover the regression classes this project has shipped
// fixes for: date parsing (v1.95 If-Modified-Since), header strictness
// (request smuggling), log escaping (GHSA-wxxh-8845-3c89), and the CGI
// command-line escaping pair (CVE-2026-22781, CVE-2026-27613).
//
// Build and run (from TESTS/unit, FPC 3.2.2 i386-win32):
//   fpc -B -MObjFPC -Fu..\..\SRC -Fi..\..\SRC srvtest.dpr
//   srvtest.exe
// Exit code 0 when every check passes, 1 otherwise.
{$I DEFINE.INC}
program srvtest;

{$APPTYPE CONSOLE}

uses
  Windows,
  xBase,
  SrvMain;

var
  Checks: Integer = 0;
  Failures: Integer = 0;

procedure Fail(const Name, Detail: AnsiString);
begin
  Inc(Failures);
  WriteLn('FAIL ', Name, ' ', Detail);
end;

procedure Check(const Name: AnsiString; Cond: Boolean);
begin
  Inc(Checks);
  if not Cond then
    Fail(Name, '');
end;

procedure CheckStr(const Name, Got, Want: AnsiString);
begin
  Inc(Checks);
  if Got <> Want then
    Fail(Name, 'got "' + Got + '" want "' + Want + '"');
end;

function I64toS(v: Int64): AnsiString;
var
  s: ShortString;
begin
  Str(v, s);
  Result := s;
end;

procedure CheckInt(const Name: AnsiString; Got, Want: Int64);
begin
  Inc(Checks);
  if Got <> Want then
    Fail(Name, 'got ' + I64toS(Got) + ' want ' + I64toS(Want));
end;

procedure TestFileTime;
var
  t: DWORD;
begin
  CheckStr('FileTimeToStr epoch', FileTimeToStr(0), 'Thu, 01 Jan 1970 00:00:00 GMT');
  CheckInt('StrToFileTime epoch', StrToFileTime('Thu, 01 Jan 1970 00:00:00 GMT'), 0);

  // The v1.95 regression class: the round trip must return the input second.
  t := 1756000000;
  CheckInt('StrToFileTime round trip', StrToFileTime(FileTimeToStr(t)), t);

  Check('StrToFileTime RFC 850 form',
    (StrToFileTime('Sunday, 06-Nov-94 08:49:37 GMT') <> INVALID_FILE_TIME) and
    (StrToFileTime('Sunday, 06-Nov-94 08:49:37 GMT') =
     StrToFileTime('Sun, 06 Nov 1994 08:49:37 GMT')));
  Check('StrToFileTime two-digit year under 50 is 2000s',
    StrToFileTime('Thu, 01 Jan 26 00:00:00 GMT') =
    StrToFileTime('Thu, 01 Jan 2026 00:00:00 GMT'));
  CheckInt('StrToFileTime bad month',
    StrToFileTime('Sun, 06 Xxx 1994 08:49:37 GMT'), Int64(INVALID_FILE_TIME));
  CheckInt('StrToFileTime empty', StrToFileTime(''), Int64(INVALID_FILE_TIME));
end;

procedure TestLogEscaping;
begin
  CheckStr('StripCRLF', StripCRLF('a'#13#10'b'#13), 'ab');
  CheckStr('StripCRLF plain', StripCRLF('plain'), 'plain');

  CheckStr('EscapeForLog plain', EscapeForLog('normal-1'), 'normal-1');
  CheckStr('EscapeForLog NUL', EscapeForLog(#0), '#00');
  CheckStr('EscapeForLog unit separator', EscapeForLog(#31), '#1F');
  CheckStr('EscapeForLog DEL', EscapeForLog(#127), '#7F');
  CheckStr('EscapeForLog hash', EscapeForLog('#'), '#23');
  CheckStr('EscapeForLog quote', EscapeForLog('"'), '#22');
  CheckStr('EscapeForLog backslash', EscapeForLog('\'), '#5C');
  CheckStr('EscapeForLog mixed', EscapeForLog('a'#10'b'), 'a#0Ab');
end;

procedure TestHeaderParsing;
var
  n, v: AnsiString;
begin
  Check('IsHeaderTChar letter', IsHeaderTChar('a'));
  Check('IsHeaderTChar tilde', IsHeaderTChar('~'));
  Check('IsHeaderTChar paren', not IsHeaderTChar('('));
  Check('IsHeaderTChar space', not IsHeaderTChar(' '));
  Check('IsHeaderTChar colon', not IsHeaderTChar(':'));

  Check('IsHexChar', IsHexChar('0') and IsHexChar('f') and IsHexChar('A')
    and not IsHexChar('g'));
  CheckInt('HexNibble digit', HexNibble('9'), 9);
  CheckInt('HexNibble lower', HexNibble('a'), 10);
  CheckInt('HexNibble upper', HexNibble('F'), 15);
  CheckInt('HexNibble junk', HexNibble('g'), -1);

  Check('Dangerous %00', HasDangerousPercentEncoding('%00'));
  Check('Dangerous %0a', HasDangerousPercentEncoding('%0a'));
  Check('Dangerous %0D', HasDangerousPercentEncoding('x%0Dy'));
  Check('Harmless %41', not HasDangerousPercentEncoding('%41'));
  Check('Harmless plain', not HasDangerousPercentEncoding('abc'));
  Check('Harmless truncated', not HasDangerousPercentEncoding('%4'));
  Check('Harmless bad hex', not HasDangerousPercentEncoding('%zz'));

  Check('Header ok', ParseHeaderLineStrict('Host: example.com', n, v));
  CheckStr('Header name uppercased', n, 'HOST');
  CheckStr('Header value', v, 'example.com');
  Check('Header OWS trimmed', ParseHeaderLineStrict('X-Y:  v  ', n, v) and (v = 'v'));
  Check('Header obs-fold space', not ParseHeaderLineStrict(' folded: x', n, v));
  Check('Header obs-fold tab', not ParseHeaderLineStrict(#9'x: y', n, v));
  Check('Header no colon', not ParseHeaderLineStrict('NoColon', n, v));
  Check('Header empty name', not ParseHeaderLineStrict(':v', n, v));
  Check('Header space in name', not ParseHeaderLineStrict('Bad Name: v', n, v));
  Check('Header tab inside value', ParseHeaderLineStrict('X: a'#9'b', n, v)
    and (v = 'a'#9'b'));
  Check('Header encoded CRLF', not ParseHeaderLineStrict('X: %0d%0a', n, v));
  Check('Header DEL in value', not ParseHeaderLineStrict('X: '#127, n, v));
  Check('Header raw CR', not ParseHeaderLineStrict('X'#13': v', n, v));
end;

procedure TestCgiEscaping;
begin
{$IFDEF STRICT_CGI_PARAMS}
  Check('QueryParam plain', IsQueryParamSafe('abc'));
  // Pinned actual behavior: the empty query parameter is accepted.
  Check('QueryParam empty', IsQueryParamSafe(''));
  Check('QueryParam leading hyphen', not IsQueryParamSafe('-x'));
  Check('QueryParam space', not IsQueryParamSafe('a b'));
  Check('QueryParam metachar', not IsQueryParamSafe('a&b'));
  Check('QueryParam path chars', IsQueryParamSafe('C:/dir\file.txt'));
  Check('QueryParam quote', not IsQueryParamSafe('a"b'));
{$ENDIF}

  // The whole parameter is wrapped in double quotes on top of the caret
  // escaping, matching the Apache ap_escape_shell_cmd contract.
  CheckStr('Escape plain', EscapeShellParam('abc'), '"abc"');
  CheckStr('Escape ampersand', EscapeShellParam('a&b'), '"a^&b"');
  CheckStr('Escape redirects', EscapeShellParam('<>|'), '"^<^>^|"');
  CheckStr('Escape percent', EscapeShellParam('%'), '"^%"');
  CheckStr('Escape caret', EscapeShellParam('^'), '"^^"');
  CheckStr('Escape parens', EscapeShellParam('()'), '"^(^)"');
  CheckStr('Escape dollar', EscapeShellParam('$HOME'), '"^$HOME"');
  // CVE-2026-27613: the double quote takes a backslash, not a caret,
  // because MSVCRT argument parsing reads \" as a literal quote.
  CheckStr('Escape double quote', EscapeShellParam('"'), '"\""');
  CheckStr('Escape single quote', EscapeShellParam(''''), '"^''"');
  CheckStr('Escape drops newlines', EscapeShellParam('a'#10'b'#13), '"ab"');
end;

procedure TestUrlAndAddr;
begin
  Check('IsURL yes', IsURL('http://x'));
  Check('IsURL no', not IsURL('a/b'));

  CheckInt('Adr2Int dotted', Adr2Int('1.2.3.4'), $04030201);
  CheckInt('Adr2Int localhost', Adr2Int('127.0.0.1'), $0100007F);
  CheckInt('Adr2Int zero', Adr2Int('0.0.0.0'), 0);
  CheckInt('Adr2Int octet over 255', Adr2Int('300.1.1.1'), Integer($FFFFFFFF));
  CheckInt('Adr2Int last octet over 255', Adr2Int('1.2.3.256'), Integer($FFFFFFFF));
  Check('_Adr2Int needs the closing dot', _Adr2Int('1.2.3.4.') = DWORD($04030201));
end;

begin
  TestFileTime;
  TestLogEscaping;
  TestHeaderParsing;
  TestCgiEscaping;
  TestUrlAndAddr;

  WriteLn(Checks, ' checks, ', Failures, ' failures');
  if Failures > 0 then
    Halt(1);
end.
