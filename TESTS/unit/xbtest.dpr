// Unit tests for SRC/xBase.pas: every free function of the interface that a
// console program can exercise deterministically, the TColl family, and
// smoke tests for the OS-bound wrappers (events, files, environment,
// registry reads, winsock address conversion).
//
// Build and run (from TESTS/unit, FPC 3.2.2 i386-win32):
//   fpc -B -MObjFPC -Fu..\..\SRC -Fi..\..\SRC xbtest.dpr
//   xbtest.exe
// Exit code 0 when every check passes, 1 otherwise; failures print one line each.
program xbtest;

{$APPTYPE CONSOLE}

uses
  Windows,
  WinSock,
  xBase;

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

procedure TestStringRoutines;
var
  s, w: AnsiString;
  cs: TCharSet;
begin
  CheckStr('AddRightSpaces pad', AddRightSpaces('ab', 5), 'ab   ');
  CheckStr('AddRightSpaces trunc', AddRightSpaces('abcdef', 3), 'abc');

  s := 'ab';
  AddStr(s, 'c');
  CheckStr('AddStr', s, 'abc');

  Check('CompareStr lt', CompareStr('a', 'b') < 0);
  Check('CompareStr gt', CompareStr('b', 'a') > 0);
  CheckInt('CompareStr eq', CompareStr('a', 'a'), 0);
  Check('CompareStr prefix', CompareStr('a', 'ab') < 0);
  CheckInt('CompareStr empty', CompareStr('', ''), 0);

  CheckStr('CopyLeft', CopyLeft('abcdef', 3), 'cdef');
  s := 'abcdef';
  DeleteLeft(s, 3);
  CheckStr('DeleteLeft keeps the head', s, 'ab');

  s := 'a   b';
  DelDoubles('  ', s);
  CheckStr('DelDoubles', s, 'a b');

  s := 'abc';
  DelFC(s);
  CheckStr('DelFC', s, 'bc');
  s := 'abc';
  DelLC(s);
  CheckStr('DelLC', s, 'ab');
  s := 'a';
  DelLC(s);
  CheckStr('DelLC single', s, '');
  s := '';
  DelLC(s);
  CheckStr('DelLC empty', s, '');

  CheckStr('DelLeft', DelLeft(#9' x '), 'x ');
  CheckStr('DelRight', DelRight(' x '#9), ' x');
  CheckStr('DelSpaces', DelSpaces('  x  '), 'x');

  Check('DigitsOnly digits', DigitsOnly('007'));
  Check('DigitsOnly mixed', not DigitsOnly('1a'));
  Check('DigitsOnly empty', not DigitsOnly(''));

  FillCharSet('abc', cs);
  Check('FillCharSet member', 'a' in cs);
  Check('FillCharSet non-member', not ('d' in cs));

  s := 'one two';
  Check('GetWrd not last', not GetWrd(s, w, ' '));
  CheckStr('GetWrd word 1', w, 'one');
  Check('GetWrd last', GetWrd(s, w, ' '));
  CheckStr('GetWrd word 2', w, 'two');
  s := '  a b ';
  GetWrd(s, w, ' ');
  CheckStr('GetWrd trims on space delimiter', w, 'a');
  CheckStr('GetWrd remainder', s, 'b');

  s := 'day 25 Aug';
  Check('GetWrdD', GetWrdD(s, w));
  CheckStr('GetWrdD digits', w, '25');
  CheckStr('GetWrdD remainder', s, 'Aug');
  s := '';
  Check('GetWrdD empty', not GetWrdD(s, w));

  s := 'Aug 2026';
  Check('GetWrdA', GetWrdA(s, w));
  CheckStr('GetWrdA letters', w, 'Aug');
  CheckStr('GetWrdA remainder', s, '2026');

  s := 'GET /x HTTP/1.0';
  GetWrdStrict(s, w);
  CheckStr('GetWrdStrict word', w, 'GET');
  GetWrdStrictUC(s, w);
  CheckStr('GetWrdStrictUC uppercases', w, '/X');

  CheckStr('Hex2', Hex2($AB), 'ab');
  CheckStr('Hex4', Hex4($12AB), '12ab');
  CheckStr('Hex8', Hex8($DEADBEEF), 'deadbeef');
  CheckStr('Int2Hex strips zeros', Int2Hex($1A2B), '1a2b');
  CheckStr('Int2Hex zero', Int2Hex(0), '0');

  CheckStr('ItoS', ItoS(-5), '-5');
  CheckStr('ItoSz', ItoSz(7, 3), '007');
  CheckStr('Int2Str thousands', Int2Str(1234567), '1,234,567');
  CheckStr('Int2Str short', Int2Str(123), '123');
  CheckStr('Int2Str four digits', Int2Str(1000), '1,000');

  CheckInt('LastDelimiter', LastDelimiter('\:', 'C:\a\b'), 5);
  CheckInt('LastDelimiter absent', LastDelimiter('xyz', 'abc'), 0);

  CheckStr('LowerCase', LowerCase('AbC1'), 'abc1');
  CheckStr('UpperCase', UpperCase('aBc1'), 'ABC1');

  CheckStr('MonthE Jan', MonthE(1), 'Jan');
  CheckStr('MonthE Dec', MonthE(12), 'Dec');

  s := 'aaa';
  Check('Replace hits', Replace('a', 'bb', s));
  CheckStr('Replace all occurrences', s, 'bbbbbb');
  s := 'xyz';
  Check('Replace misses', not Replace('q', 'r', s));
  s := 'ab';
  Replace('b', 'bb', s);
  CheckStr('Replace no rescan of insertion', s, 'abb');

  Check('StrEnds yes', StrEnds('hello.txt', '.txt'));
  Check('StrEnds no', not StrEnds('a', 'ab'));
  CheckStr('StrRight', StrRight('hello', 3), 'llo');

  CheckStr('WipeChars', WipeChars('a-b-c', '-'), 'abc');
  CheckStr('StrAsg', StrAsg('abc'), 'abc');
end;

procedure TestNumeric;
var
  v: Integer;
begin
  Check('_Val empty is False', not _Val('', v));
  Check('_Val zero', _Val('0', v) and (v = 0));
  Check('_Val max', _Val('2147483647', v) and (v = 2147483647));
  Check('_Val overflow', not _Val('2147483648', v));
  Check('_Val junk', not _Val('12a', v));
  Check('_Val space', not _Val(' 1', v));
  Check('_Val sign rejected', not _Val('-1', v));

  CheckInt('Vl plain', Vl('123'), 123);
  CheckInt('Vl nine digits', Vl('999999999'), 999999999);
  CheckInt('Vl ten digits invalid', Vl('1234567890'), Int64(INVALID_VALUE));
  CheckInt('Vl junk invalid', Vl('12a'), Int64(INVALID_VALUE));
  // Pinned actual behavior: the empty string answers 0, not INVALID_VALUE,
  // because the digit loop never runs and the accumulator is returned.
  CheckInt('Vl empty answers zero', Vl(''), 0);

  CheckInt('VlH lower', VlH('ff'), 255);
  CheckInt('VlH upper', VlH('FF'), 255);
  CheckInt('VlH zero', VlH('0'), 0);
  CheckInt('VlH leading zeros skipped', VlH('00000000ff'), 255);
  CheckInt('VlH empty invalid', VlH(''), Int64(INVALID_VALUE));
  CheckInt('VlH nine significant invalid', VlH('123456789'), Int64(INVALID_VALUE));
  CheckInt('VlH junk invalid', VlH('xy'), Int64(INVALID_VALUE));
end;

procedure TestBasicRoutines;
var
  buf: array [0 .. 7] of AnsiChar;
  b1, b2: array [0 .. 3] of Byte;
  a, b: Integer;
begin
  buf[0] := 'a';
  buf[1] := 'b';
  buf[2] := #0;
  CheckInt('NulSearch', NulSearch(buf), 2);
  CheckStr('Buf2Str', Buf2Str(buf), 'ab');

  b1[0] := 1; b1[1] := 2; b1[2] := 3; b1[3] := 4;
  b2 := b1;
  Check('CompareMem equal', CompareMem(@b1, @b2, 4));
  Check('MemEqu equal', MemEqu(b1, b2, 4));
  b2[3] := 9;
  Check('CompareMem differs', not CompareMem(@b1, @b2, 4));
  Check('MemEqu differs', not MemEqu(b1, b2, 4));

  Clear(b1, SizeOf(b1));
  Check('Clear zeroes', (b1[0] = 0) and (b1[3] = 0));

  CheckInt('MaxI', MaxI(-1, 1), 1);
  CheckInt('MinI', MinI(-1, 1), -1);
  Check('MaxD unsigned', MaxD($FFFFFFFF, 1) = $FFFFFFFF);
  Check('MinD unsigned', MinD($FFFFFFFF, 1) = 1);

  CheckInt('NumBits one', NumBits(1), 1);
  CheckInt('NumBits two', NumBits(2), 2);
  CheckInt('NumBits byte', NumBits(255), 8);
  CheckInt('NumBits top bit', NumBits(Integer($80000000)), 32);

  a := 255;
  b := 15;
  LowerPrec(a, b, 4);
  CheckInt('LowerPrec a', a, 15);
  CheckInt('LowerPrec b', b, 0);

  a := 1;
  b := 2;
  XChg(a, b);
  Check('XChg', (a = 2) and (b = 1));
  a := 5;
  b := 3;
  XAdd(a, b);
  Check('XAdd', (a = 8) and (b = 5));
end;

procedure TestRfc;
var
  s: AnsiString;
begin
  Check('__alpha letter', __alpha('x'));
  Check('__alpha digit', not __alpha('5'));
  Check('__digit', __digit('5') and not __digit('x'));
  Check('__ctl nul', __ctl(#0));
  Check('__ctl del', __ctl(#127));
  Check('__ctl printable', not __ctl('A'));
  Check('__safe', __safe('-') and __safe('.') and not __safe('&'));
  Check('__extra', __extra('!') and not __extra('-'));
  Check('__reserved', __reserved('/') and __reserved('?') and not __reserved('-'));
  Check('__unsafe', __unsafe('%') and __unsafe('<') and not __unsafe('a'));
  Check('__pchar colon', __pchar(':'));
  Check('__pchar slash is not pchar', not __pchar('/'));
  Check('__uchar letter', __uchar('a'));
  Check('__uchar percent', not __uchar('%'));

  s := '%41bc';
  Check('UnpackPchars decodes', UnpackPchars(s));
  CheckStr('UnpackPchars result', s, 'Abc');
  s := 'a/b';
  Check('UnpackPchars allows slash', UnpackPchars(s));
  s := 'a/b';
  Check('UnpackUchars rejects slash', not UnpackUchars(s));
  s := 'a%4';
  Check('UnpackPchars truncated escape', not UnpackPchars(s));
  s := '%GG';
  Check('UnpackPchars bad hex', not UnpackPchars(s));
  s := '%3f';
  Check('UnpackPchars lowercase hex', UnpackPchars(s));
  CheckStr('UnpackPchars lowercase result', s, '?');

  s := 'plain';
  Check('ProcessQuotes plain', ProcessQuotes(s));
  CheckStr('ProcessQuotes unchanged', s, 'plain');
  s := 'a"bc"d';
  Check('ProcessQuotes quoted', ProcessQuotes(s));
  CheckStr('ProcessQuotes encodes quoted span', s, 'a%62%63d');
  s := 'a"b';
  Check('ProcessQuotes unbalanced', not ProcessQuotes(s));
  s := #9;
  Check('ProcessQuotes rejects TAB', not ProcessQuotes(s));
end;

procedure TestPaths;
var
  Path, Name, Ext: AnsiString;
begin
  CheckStr('ExtractFilePath', ExtractFilePath('C:\a\b.c'), 'C:\a\');
  CheckStr('ExtractFileDir', ExtractFileDir('C:\a\b.c'), 'C:\a');
  CheckStr('ExtractFileDir root', ExtractFileDir('C:\b.c'), 'C:\');
  CheckStr('ExtractFileDrive', ExtractFileDrive('C:\a'), 'C:');
  CheckStr('ExtractFileDrive UNC', ExtractFileDrive('\\srv\share\x'), '\\srv\share');
  CheckStr('ExtractFileName', ExtractFileName('C:\a\b.c'), 'b.c');
  CheckStr('ExtractFileExt', ExtractFileExt('C:\a\b.c'), '.c');
  CheckStr('ExtractFileExt none', ExtractFileExt('C:\a.d\b'), '');
  CheckStr('ExtractFileRoot', ExtractFileRoot('C:\x\y'), 'C:\');
  CheckStr('ExtractDir trims slash', ExtractDir('C:\a\'), 'C:\a');
  CheckStr('ExtractDir keeps root', ExtractDir('C:\'), 'C:\');

  FSplit('C:\dir\name.ext', Path, Name, Ext);
  Check('FSplit full', (Path = 'C:\dir\') and (Name = 'name') and (Ext = '.ext'));
  FSplit('name', Path, Name, Ext);
  Check('FSplit bare', (Path = '') and (Name = 'name') and (Ext = ''));
  FSplit('a.b.c', Path, Name, Ext);
  Check('FSplit last dot wins', (Name = 'a.b') and (Ext = '.c'));

  CheckStr('MakeNormName', MakeNormName('C:\a', 'b'), 'C:\a\b');
  CheckStr('MakeNormName trailing', MakeNormName('C:\a\', 'b'), 'C:\a\b');
  CheckStr('MakeNormName empty dir', MakeNormName('', 'b'), 'b');

  CheckStr('MakeFullDir relative', MakeFullDir('C:\base', 'sub'), 'C:\base\sub');
  CheckStr('MakeFullDir rooted', MakeFullDir('C:\base', '\sub'), 'C:\sub');
  CheckStr('MakeFullDir drive', MakeFullDir('C:\base', 'D:\x'), 'D:\x');
  CheckStr('MakeFullDir UNC', MakeFullDir('C:\base', '\\srv\x'), '\\srv\x');

  CheckStr('ExpandFileName collapses dots', ExpandFileName('C:\foo\..\bar'), 'C:\bar');
  CheckStr('ExpandFileName empty', ExpandFileName(''), '');
end;

procedure TestMask;
begin
  Check('MatchMask star', MatchMask('FILE.TXT', '*.txt'));
  Check('MatchMask question', MatchMask('file.txt', 'f?le.*'));
  Check('MatchMask miss', not MatchMask('file.txt', '*.doc'));
  Check('MatchMask exact', MatchMask('abc', 'abc'));
  Check('MatchMask shorter mask', not MatchMask('abc', 'ab'));
  Check('MatchMask trailing star', MatchMask('abc', 'a*c*'));
  Check('_MatchMask percent digit', _MatchMask('file2.txt', 'file%.txt', True));
  Check('_MatchMask percent letter', not _MatchMask('fileX.txt', 'file%.txt', True));
  Check('_MatchMaskBody plain', _MatchMaskBody('ABC', 'A*C', False));
end;

procedure TestTime;
var
  L, H, t: DWORD;
begin
  t := 1756000000;
  uCvtSetFileTime(t, L, H);
  CheckInt('uCvt round trip', uCvtGetFileTime(L, H), t);
  CheckInt('uCvtGetFileTime before epoch', uCvtGetFileTime(0, 0), 0);
  Check('uGetSystemTime is current', uGetSystemTime > 1700000000);
end;

type
  TProbe = class(TAdvObject)
  end;

function CmpPtr(Item1, Item2: Pointer): Int64;
begin
  Result := Int64(NativeUInt(Item1)) - Int64(NativeUInt(Item2));
end;

procedure TestColl;
var
  c: TColl;
  o1, o2, o3: TProbe;
begin
  o1 := TProbe.Create;
  o2 := TProbe.Create;
  o3 := TProbe.Create;
  c := TColl.Create;
  c.Add(o1);
  c.Add(o2);
  CheckInt('TColl Count', c.Count, 2);
  Check('TColl At', c.At(0) = Pointer(o1));
  CheckInt('TColl IndexOf', c.IndexOf(o2), 1);
  CheckInt('TColl IndexOf absent', c.IndexOf(o3), -1);
  c.AtInsert(0, o3);
  Check('TColl AtInsert shifts', (c.At(0) = Pointer(o3)) and (c.At(1) = Pointer(o1)));
  c.MoveTo(0, 2);
  Check('TColl MoveTo', c.At(2) = Pointer(o3));
  c.AtDelete(2);
  CheckInt('TColl AtDelete', c.Count, 2);
  c.AtPut(1, nil);
  c.Pack;
  CheckInt('TColl Pack removes nil', c.Count, 1);
  c.Enter;
  c.Leave;
  c.DeleteAll;
  CheckInt('TColl DeleteAll', c.Count, 0);
  c.Free;
  o1.Free;
  o2.Free;
  o3.Free;

  c := TColl.Create;
  c.Add(Pointer(NativeUInt(3)));
  c.Add(Pointer(NativeUInt(1)));
  c.Add(Pointer(NativeUInt(2)));
  c.Sort(@CmpPtr);
  Check('TColl Sort', (c.At(0) = Pointer(NativeUInt(1))) and
    (c.At(1) = Pointer(NativeUInt(2))) and (c.At(2) = Pointer(NativeUInt(3))));
  c.DeleteAll;
  c.Free;
end;

procedure TestStringColl;
var
  sc, sc2: TStringColl;
  key: AnsiString;
  i: Integer;
begin
  sc := TStringColl.Create;
  sc.Ins('pear');
  sc.Ins('apple');
  sc.Ins('mango');
  Check('TStringColl sorted insert',
    (sc[0] = 'apple') and (sc[1] = 'mango') and (sc[2] = 'pear'));
  Check('TStringColl Found', sc.Found('mango'));
  Check('TStringColl Found miss', not sc.Found('kiwi'));
  Check('TStringColl FoundU', sc.FoundU('pear'));
  Check('TStringColl FoundUC', sc.FoundUC('PEAR'));
  CheckInt('TStringColl IdxOf', sc.IdxOf('mango'), 1);
  i := -1;
  key := 'apple';
  Check('TSortedColl Search hit', sc.Search(@key, i));
  CheckInt('TSortedColl Search index', i, 0);
  key := 'banana';
  Check('TSortedColl Search miss', not sc.Search(@key, i));
  CheckInt('TSortedColl miss insertion point', i, 1);
  sc.Ins('apple');
  CheckInt('TSortedColl rejects duplicate', sc.Count, 3);
  sc.Duplicates := True;
  sc.Ins('apple');
  CheckInt('TSortedColl allows duplicate when set', sc.Count, 4);
  sc.Free;

  sc := TStringColl.Create;
  sc.Add('b');
  sc.Add('a');
  Check('TStringColl Add keeps order', (sc[0] = 'b') and (sc[1] = 'a'));
  sc[1] := 'z';
  CheckStr('TStringColl SetString', sc[1], 'z');
  sc.AtIns(1, 'm');
  CheckStr('TStringColl AtIns', sc[1], 'm');
  CheckStr('TStringColl LongString', sc.LongString, 'b'#13#10'm'#13#10'z'#13#10);
  CheckStr('TStringColl LongStringD', sc.LongStringD(','), 'b,m,z');

  sc2 := TStringColl(sc.Copy);
  sc2[0] := 'q';
  Check('TStringColl Copy is deep', (sc[0] = 'b') and (sc2[0] = 'q'));

  sc.Fill(['x', 'y']);
  Check('TStringColl Fill', (sc.Count = 2) and (sc[0] = 'x'));
  sc2.FreeAll;
  sc.AppendTo(sc2);
  CheckInt('TStringColl AppendTo', sc2.Count, 2);
  sc.Concat(sc2);
  Check('TStringColl Concat moves', (sc.Count = 4) and (sc2.Count = 0));
  sc.Free;
  sc2.Free;

  sc := TStringColl.Create;
  sc.FillEnum('a,b,c', ',', False);
  Check('TStringColl FillEnum', (sc.Count = 3) and (sc[0] = 'a') and (sc[2] = 'c'));
  sc.FreeAll;
  sc.SetTextStr('x'#13#10'y'#10'z');
  Check('TStringColl SetTextStr', (sc.Count = 3) and (sc[1] = 'y') and (sc[2] = 'z'));
  sc.Free;
end;

procedure TestEvents;
var
  h: THandle;
  arr: TWOHandleArray;
begin
  h := CreateEvt(True);
  arr[0] := h;
  CheckInt('WaitEvtA manual signaled', WaitEvtA(1, @arr, 0), WAIT_OBJECT_0);
  Check('ClearHandle open handle', ClearHandle(h));
  Check('ClearHandle already invalid', not ClearHandle(h));

  h := CreateEvtA;
  arr[0] := h;
  CheckInt('WaitEvtA auto unsignaled', WaitEvtA(1, @arr, 0), WAIT_TIMEOUT);
  SetEvent(h);
  CheckInt('WaitEvtA auto signaled', WaitEvtA(1, @arr, 0), WAIT_OBJECT_0);
  CheckInt('WaitEvtA auto reset consumed', WaitEvtA(1, @arr, 0), WAIT_TIMEOUT);
  // Pinned actual behavior: SignaledEvt compares the WaitForSingleObject
  // result against the handle value rather than WAIT_OBJECT_0, so it answers
  // False even for a signaled event. Nothing in the server calls it today.
  SetEvent(h);
  Check('SignaledEvt pinned behavior', not SignaledEvt(h));
  Check('ZeroHandle open handle', ZeroHandle(h));
  Check('ZeroHandle zero', not ZeroHandle(h));
end;

procedure TestFilesAndEnv;
var
  dir, fname, big: AnsiString;
  h: THandle;
  written: DWORD;
  Info: TFileInfo;
  i: Integer;
begin
  dir := GetEnvVariable('TEMP');
  Check('GetEnvVariable TEMP set', dir <> '');
  fname := MakeNormName(dir, 'xbtest_tmp.bin');

  h := _CreateFile(fname, [cWrite, cTruncate]);
  Check('_CreateFile create', h <> INVALID_HANDLE_VALUE);
  WriteFile(h, PAnsiChar('hello')^, 5, written, nil);
  CheckInt('WriteFile wrote', written, 5);
  Check('GetFileNfoByHandle', GetFileNfoByHandle(h, Info) and (Info.Size = 5));
  CloseHandle(h);

  Check('FileExists yes', FileExists(fname));
  CheckInt('_GetFileSize', _GetFileSize(fname), 5);
  Check('GetFileNfo', GetFileNfo(fname, Info, False) and (Info.Size = 5));
  Check('GetFileNfo time is current', Info.Time + 300 > uGetSystemTime);
  DeleteFileA(PAnsiChar(fname));
  Check('FileExists no', not FileExists(fname));
  Check('_CreateFile empty name', _CreateFile('', [cRead]) = INVALID_HANDLE_VALUE);
  Check('_GetFileSize missing', _GetFileSize(fname) = INVALID_FILE_SIZE);

  SetEnvironmentVariableA('XBTEST_SHORT', 'hello');
  CheckStr('GetEnvVariable short', GetEnvVariable('XBTEST_SHORT'), 'hello');
  big := '';
  for i := 1 to 200 do
    AddStr(big, AnsiChar(Ord('a') + (i mod 26)));
  SetEnvironmentVariableA('XBTEST_LONG', PAnsiChar(big));
  CheckStr('GetEnvVariable beyond the first buffer', GetEnvVariable('XBTEST_LONG'), big);
  CheckStr('GetEnvVariable missing', GetEnvVariable('XBTEST_ABSENT'), '');
  CheckStr('GetEnvVariable empty name', GetEnvVariable(''), '');
end;

procedure TestRegistryAndSys;
var
  k: HKey;
  s: AnsiString;
begin
  Check('OpenRegKey empty name', OpenRegKey('') = INVALID_REGISTRY_KEY);
  k := OpenRegKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion');
  Check('OpenRegKey HKLM subkey', k <> INVALID_REGISTRY_KEY);
  if k <> INVALID_REGISTRY_KEY then
  begin
    s := ReadRegString(k, 'CurrentVersion');
    Check('ReadRegString value', s <> '');
    CheckStr('ReadRegString missing value', ReadRegString(k, 'XbTestNoSuchValue'), '');
    RegCloseKey(k);
  end;
  Check('WriteRegString refuses empty', not WriteRegString(0, '', 'x'));
  Check('WriteRegInt refuses empty', not WriteRegInt(0, '', 1));
  Check('SysErrorMsg nonempty', SysErrorMsg(2) <> '');
end;

procedure TestWinsockAndUnicode;
begin
  CheckStr('AddrInet localhost', AddrInet($0100007F), '127.0.0.1');
  CheckStr('AddrInet round trip', AddrInet(Inet2addr('1.2.3.4')), '1.2.3.4');
  CheckInt('Inet2addr empty', Inet2addr(''), 0);
  CheckStr('UnicodeStringToRawByteString ascii',
    UnicodeStringToRawByteString('Hello', 1252), 'Hello');
  CheckStr('UnicodeStringToRawByteString empty',
    UnicodeStringToRawByteString('', 1252), '');
end;

var
  wsa: TWSAData;
begin
  WSAStartup($0202, wsa);
  xBaseInit;

  TestStringRoutines;
  TestNumeric;
  TestBasicRoutines;
  TestRfc;
  TestPaths;
  TestMask;
  TestTime;
  TestColl;
  TestStringColl;
  TestEvents;
  TestFilesAndEnv;
  TestRegistryAndSys;
  TestWinsockAndUnicode;

  xBaseDone;
  WSACleanup;

  WriteLn(Checks, ' checks, ', Failures, ' failures');
  if Failures > 0 then
    Halt(1);
end.
