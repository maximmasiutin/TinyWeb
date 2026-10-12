// Unit tests for the pure parsing and escaping helpers of SRC/SrvMain.pas,
// reached through the declarations the unit exposes in its interface section.
// Table-driven cases cover the regression classes this project has shipped
// fixes for: date parsing (v1.95 If-Modified-Since), header strictness
// (request smuggling), log escaping (GHSA-wxxh-8845-3c89), and the CGI
// command-line escaping pair (CVE-2026-22781, CVE-2026-27613), and the CGI
// Location classification with the filesystem-path spelling policy.
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

procedure TestLocation;
begin
  Check('Location URL', ClassifyLocation('http://x') = lkURL);
  Check('Location URL with port, path and query',
    ClassifyLocation('https://example.invalid:8443/a?b=c') = lkURL);
  Check('Location scheme with + - .', ClassifyLocation('svn+ssh.x-y://h/r') = lkURL);
  Check('Location drive path', ClassifyLocation('C:\www\page.html') = lkFilePath);
  Check('Location lower-case drive', ClassifyLocation('c:\www') = lkFilePath);
  Check('Location relative path', ClassifyLocation('a/b') = lkRefused);
  Check('Location RFC 3875 local redirect', ClassifyLocation('/page.html') = lkRefused);
  Check('Location scheme separator later in the value',
    ClassifyLocation('/go?to=http://x') = lkRefused);
  Check('Location scheme starting with a digit', ClassifyLocation('1http://x') = lkRefused);
  Check('Location empty scheme', ClassifyLocation('://x') = lkRefused);
  Check('Location scheme with a forbidden character',
    ClassifyLocation('ht_tp://x') = lkRefused);
  Check('Location drive-relative', ClassifyLocation('C:page.html') = lkRefused);
  Check('Location rooted without a drive', ClassifyLocation('\www\page.html') = lkRefused);
  Check('Location UNC', ClassifyLocation('\\srv\share\a') = lkRefused);
  Check('Location extended-length prefix', ClassifyLocation('\\?\C:\www\a') = lkRefused);
  Check('Location device prefix', ClassifyLocation('\\.\C:\www\a') = lkRefused);
  Check('Location empty', ClassifyLocation('') = lkRefused);
  Check('Location NUL', ClassifyLocation('C:\www\a'#0'.txt') = lkRefused);
  Check('Location tab in a URL', ClassifyLocation('http://x/'#9) = lkRefused);
  Check('Location DEL', ClassifyLocation('C:\www\a'#127) = lkRefused);
  Check('Location 8191 bytes', ClassifyLocation('http://x/' +
    StringOfChar('a', 8191 - 9)) = lkURL);
  Check('Location 8192 bytes', ClassifyLocation('http://x/' +
    StringOfChar('a', 8192 - 9)) = lkRefused);
end;

procedure TestPathSpelling;
begin
  Check('Spelling plain', LocalPathSpellingOK('C:\www\page.html'));
  Check('Spelling nested', LocalPathSpellingOK('C:\www\sub\index.html'));
  Check('Spelling spaces inside names', LocalPathSpellingOK('C:\My Files\a b.txt'));
  Check('Spelling leading and inner dots', LocalPathSpellingOK('C:\www\.well\a.b.c'));
  Check('Spelling tilde', LocalPathSpellingOK('C:\www\PROGRA~1\a'));
  Check('Spelling high byte', LocalPathSpellingOK('C:\www\'#$E9'.txt'));
  Check('Spelling device-like name', LocalPathSpellingOK('C:\www\console.txt'));
  Check('Spelling 259 bytes', LocalPathSpellingOK('C:\' + StringOfChar('a', 256)));
  Check('Spelling 260 bytes', not LocalPathSpellingOK('C:\' + StringOfChar('a', 257)));
  Check('Spelling forward slash', not LocalPathSpellingOK('C:\www/page.html'));
  Check('Spelling dot-dot', not LocalPathSpellingOK('C:\www\sub\..\cgi-bin\a.exe'));
  Check('Spelling dot', not LocalPathSpellingOK('C:\www\.\a'));
  Check('Spelling doubled backslash', not LocalPathSpellingOK('C:\www\\a'));
  Check('Spelling trailing backslash', not LocalPathSpellingOK('C:\www\'));
  Check('Spelling bare drive root', not LocalPathSpellingOK('C:\'));
  Check('Spelling inner trailing dot', not LocalPathSpellingOK('C:\www\cgi-bin.\a.exe'));
  Check('Spelling inner trailing space', not LocalPathSpellingOK('C:\www\cgi-bin \a.exe'));
  Check('Spelling final trailing dot', not LocalPathSpellingOK('C:\www\a.txt.'));
  Check('Spelling final trailing space', not LocalPathSpellingOK('C:\www\a.txt '));
  Check('Spelling alternate data stream', not LocalPathSpellingOK('C:\www\a.txt::$DATA'));
  Check('Spelling index allocation',
    not LocalPathSpellingOK('C:\www\cgi-bin::$INDEX_ALLOCATION\a.exe'));
  Check('Spelling star', not LocalPathSpellingOK('C:\www\*.txt'));
  Check('Spelling question mark', not LocalPathSpellingOK('C:\www\a?.txt'));
  Check('Spelling double quote', not LocalPathSpellingOK('C:\www\a"b'));
  Check('Spelling angle brackets', not LocalPathSpellingOK('C:\www\a<b') and
    not LocalPathSpellingOK('C:\www\a>b'));
  Check('Spelling pipe', not LocalPathSpellingOK('C:\www\a|b'));
  Check('Spelling NUL', not LocalPathSpellingOK('C:\www\a'#0'b'));
  Check('Spelling tab', not LocalPathSpellingOK('C:\www\a'#9'b'));
  Check('Spelling DEL', not LocalPathSpellingOK('C:\www\a'#127'b'));
  Check('Spelling device', not LocalPathSpellingOK('C:\www\con'));
  Check('Spelling device with extension', not LocalPathSpellingOK('C:\www\NUL.txt'));
  Check('Spelling device as a directory', not LocalPathSpellingOK('C:\www\COM1\a.txt'));
  Check('Spelling no drive', not LocalPathSpellingOK('\www\a'));
  Check('Spelling drive-relative', not LocalPathSpellingOK('C:www\a'));
  Check('Spelling UNC', not LocalPathSpellingOK('\\srv\share\a'));
  Check('Spelling extended-length prefix', not LocalPathSpellingOK('\\?\C:\www\a'));
  Check('Spelling digit as the drive', not LocalPathSpellingOK('1:\www\a'));
  Check('Spelling empty', not LocalPathSpellingOK(''));
  // Code page 932: $95 $5C is one character, and its $5C no separator.
  Check('Spelling 932 trail byte $5C', LocalPathSpellingOK('C:\www\'#$95#$5C'\a.txt', 932));
  Check('Spelling same bytes in 1252: an empty component',
    not LocalPathSpellingOK('C:\www\'#$95#$5C'\a.txt', 1252));
  Check('Spelling 932 NUL after a lead byte',
    not LocalPathSpellingOK('C:\www\'#$95#0'a.txt', 932));
  Check('Spelling 932 tab after a lead byte',
    not LocalPathSpellingOK('C:\www\'#$95#9'a.txt', 932));

  Check('Device CON', IsReservedDeviceName('CON'));
  Check('Device lower case', IsReservedDeviceName('con'));
  Check('Device with extension', IsReservedDeviceName('nul.txt'));
  Check('Device with two extensions', IsReservedDeviceName('NUL.tar.gz'));
  Check('Device with a space before the dot', IsReservedDeviceName('CON .txt'));
  Check('Device COM1', IsReservedDeviceName('COM1'));
  Check('Device LPT9 with extension', IsReservedDeviceName('lpt9.log'));
  Check('Device CLOCK$', IsReservedDeviceName('CLOCK$'));
  Check('Device CONIN$', IsReservedDeviceName('conin$'));
  Check('Device prefix only', not IsReservedDeviceName('console'));
  Check('Device COM10', not IsReservedDeviceName('COM10'));
  Check('Device leading dot', not IsReservedDeviceName('.con'));
  Check('Device empty', not IsReservedDeviceName(''));
end;

procedure TestWebRoot;
var
  s: AnsiString;
begin
  CheckStr('ResolveWebRoot empty', ResolveWebRoot(''), '');
  CheckStr('ResolveWebRoot bare drive letter is the drive root', ResolveWebRoot('C:'), 'C:');
  CheckStr('ResolveWebRoot drive root', ResolveWebRoot('C:\'), 'C:');
  CheckStr('ResolveWebRoot trailing backslash', ResolveWebRoot('C:\www\'), 'C:\www');
  CheckStr('ResolveWebRoot dot segments', ResolveWebRoot('C:\www\sub\..'), 'C:\www');
  s := ResolveWebRoot('srvtest_root');
  Check('ResolveWebRoot relative resolves against the current directory',
    (Length(s) > Length('\srvtest_root')) and (s[2] = ':') and
    (Copy(s, Length(s) - Length('\srvtest_root') + 1, MaxInt) = '\srvtest_root'));
  Check('WebRootOnDrive drive path', WebRootOnDrive(ResolveWebRoot('C:\www')));
  Check('WebRootOnDrive drive root', WebRootOnDrive(ResolveWebRoot('C:')));
  Check('WebRootOnDrive relative path', WebRootOnDrive(s));
  Check('WebRootOnDrive UNC', not WebRootOnDrive(ResolveWebRoot('\\srv\share\www')));
  Check('WebRootOnDrive extended-length prefix',
    not WebRootOnDrive(ResolveWebRoot('\\?\C:\www')));
  Check('WebRootOnDrive device prefix', not WebRootOnDrive('\\.\C:\www'));
  Check('WebRootOnDrive empty', not WebRootOnDrive(''));
end;

procedure TestUrlAndAddr;
begin
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
  TestLocation;
  TestPathSpelling;
  TestWebRoot;
  TestUrlAndAddr;

  WriteLn(Checks, ' checks, ', Failures, ' failures');
  if Failures > 0 then
    Halt(1);
end.
