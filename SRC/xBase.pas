//////////////////////////////////////////////////////////////////////////
//
// TinyWeb
// Copyright (C) 1997-2000 RIT Research Labs
// Copyright (C) 2000-2017 RITLABS S.R.L.
// Copyright (C) 2021 Maxim Masiutin
//
// This programs is free for commercial and non-commercial use as long as
// the following conditions are aheared to.
//
// Copyright remains RITLABS S.R.L., and as such any Copyright notices
// in the code are not to be removed. If this package is used in a
// product, RITLABS S.R.L. should be given attribution as the owner
// of the parts of the library used. This can be in the form of a textual
// message at program startup or in documentation (online or textual)
// provided with the package.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the copyright
// notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// 3. All advertising materials mentioning features or use of this software
// must display the following acknowledgement:
// "Based on TinyWeb Server by RITLABS S.R.L.."
//
// THIS SOFTWARE IS PROVIDED BY RITLABS S.R.L. "AS IS" AND ANY EXPRESS
// OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
// GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
// IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// The licence and distribution terms for any publically available
// version or derivative of this code cannot be changed. i.e. this code
// cannot simply be copied and put under another distribution licence
// (including the GNU Public Licence).
//
//////////////////////////////////////////////////////////////////////////

{$I DEFINE.INC}
unit xBase;

interface

uses Windows, WinSock;

const
  _INADDR_ANY = INADDR_ANY;
  INVALID_FILE_ATTRIBUTES = INVALID_FILE_SIZE;
  INVALID_FILE_TIME = INVALID_FILE_SIZE;
  INVALID_REGISTRY_KEY = INVALID_HANDLE_VALUE;
  INVALID_VALUE = INVALID_HANDLE_VALUE;

  rrLoHexChar: array [0 .. $F] of AnsiChar = '0123456789abcdef';
  rrHiHexChar: array [0 .. $F] of AnsiChar = '0123456789ABCDEF';

  SleepQuant = 1 * 60 * 1000; // 1 minute

  { Maximum TColl size }

  MaxCollSize = $20000 div SizeOf(Pointer);

const
  MMaxChars = 250;

type
  Str255 = String[255];
  TByteTable = Array [AnsiChar] of Byte;
  TBase64Table = (bsBase64, bsUUE, bsXXE);
  TUUStr = String[MMaxChars];

  TMimeCoder = class
    Table: AnsiString;
    MaxChars: Byte;
    Pad: AnsiChar;
    XChars: TByteTable;
    constructor Create(AType: TBase64Table);
    procedure InitTable;
    function Encode(const Buf; N: Byte): AnsiString;
    function EncodeBuf(const Buf; N: Byte; var OutBuf): Integer;
    function EncodeStr(const S: AnsiString): AnsiString;
    function Decode(const S: AnsiString; var Buf): Integer;
    function DecodeBuf(const SrcBuf; SrcLen: Integer; var Buf): Integer;
  end;

  TSocketOption = (soBroadcast, soDebug, soDontLinger, soDontRoute, soKeepAlive,
    soOOBInLine, soReuseAddr, soNoDelay, soBlocking, soAcceptConn);

  TSocketOptions = Set of TSocketOption;

  TSocketClass = class of TSocket;

  TSocket = class
  public
    Dead: Integer;
    FPort: DWORD;
    FAddr: DWORD;
    Handle: THandle;
    Status: Integer;
    Registered: Boolean;
    procedure RegisterSelf;
    procedure DeregisterSelf;

    function Startup: Boolean; virtual;
    function Handshake: Boolean; virtual;
    destructor Destroy; override;

    function Read(var B; Size: DWORD): DWORD;
    function Write(const B; Size: DWORD): DWORD;
    function WriteStr(const S: AnsiString): DWORD;

    function _Write(const B; Size: DWORD): DWORD; virtual;
    function _Read(var B; Size: DWORD): DWORD; virtual;

  end;

  TObjProc = procedure of object;
  TForEachProc = procedure(P: Pointer) of object;

  PFileInfo = ^TFileInfo;

  TFileInfo = record
    Attr: DWORD;
    Size: DWORD;
    Time: DWORD;
  end;

  TuFindData = record
    Info: TFileInfo;
    FName: AnsiString;
  end;

  TCreateFileMode = (

    cRead, // Specifies read access to the file
    cWrite, // Specifies write access to the file

    cFlag,

    cEnsureNew, // Creates a NEW file. The function fails
    // if the specified file already exists.

    cTruncate, // Once opened, the file is truncated so that
    // its size is zero bytes.

    cExisting, // For communications resources, console diveces

    cShareAllowWrite, cShareDenyRead,

    cOverlapped, // This flag enables more than one operation to be
    // performed simultaneously with the handle
    // (e.g. a simultaneous read and write operation).

    cRandomAccess, // Indicates that the file is accessed randomly.
    // Windows uses this flag to optimize file caching.

    cSequentialScan, // Indicates that the file is to be accessed
    // sequentially from beginning to end.

    cDeleteOnClose // Indicates that the operating system is to delete
    // the file immediately after all of its handles
    // have been closed.

    );

  TCreateFileModeSet = set of TCreateFileMode;

  { Character set type }

  PCharSet = ^TCharSet;
  TCharSet = set of AnsiChar;

  { General arrays }

  PCharArray = ^TCharArray;
  TCharArray = array [0 .. MaxLongInt - 1] of AnsiChar;

  PByteArray = ^TByteArray;
  TByteArray = array [0 .. MaxLongInt - 1] of Byte;

  PIntArray = ^TIntArray;
  TIntArray = array [0 .. (MaxLongInt div 4) - 1] of Integer;

  PDwordArray = ^TDwordArray;
  TDwordArray = array [0 .. (MaxLongInt div 4) - 1] of DWORD;

  PvIntArr = ^TvIntArr;

  TvIntArr = record
    Arr: PIntArray;
    Cnt: Integer;
  end;

  PBoolean = ^Boolean;

  PItemList = ^TItemList;
  TItemList = array [0 .. MaxCollSize - 1] of Pointer;

  TThreadMethod = procedure of object;
  TThreadPriority = (tpIdle, tpLowest, tpLower, tpNormal, tpHigher, tpHighest,
    tpTimeCritical);

{$IFDEF CONDITIONALEXPRESSIONS}
{$IF CompilerVersion >= 23.0}
{$DEFINE DELPHI_XE2_UP}
{$IFEND}
{$ENDIF}
{$IFNDEF DELPHI_XE2_UP}
  TThreadID = DWORD;
{$ENDIF}

  TThread = class
  private
    FHandle: THandle;
    FThreadID: TThreadID;
    FTerminated: Boolean;
    FSuspended: Boolean;
    FFreeOnTerminate: Boolean;
    FFinished: Boolean;
    FReturnValue: DWORD;
    function GetPriority: TThreadPriority;
    procedure SetPriority(Value: TThreadPriority);
    procedure SetSuspended(Value: Boolean);
  protected
    procedure Execute; virtual; abstract;
    property ReturnValue: DWORD read FReturnValue write FReturnValue;
    property Terminated: Boolean read FTerminated;
  public
    constructor Create(CreateSuspended: Boolean);
    destructor Destroy; override;
    procedure Resume;
    procedure Suspend;
    procedure Terminate;
    property FreeOnTerminate: Boolean read FFreeOnTerminate
      write FFreeOnTerminate;
    property Handle: THandle read FHandle;
    property Priority: TThreadPriority read GetPriority write SetPriority;
    property Suspended: Boolean read FSuspended write SetSuspended;
    property ThreadID: TThreadID read FThreadID;
  end;

  TAdvObject = class;

  TAdvObject = class
  end;

  TAdvCpObject = class(TAdvObject)
    function Copy: Pointer; virtual; abstract;
  end;

  TAdvClass = class of TAdvObject;

  TCollClass = class of TColl;

  TListSortCompare = function(Item1, Item2: Pointer): Integer;

  TColl = class(TAdvCpObject)
  protected
    FCount: Integer;
    FCapacity: Integer;
    FDelta: Integer;
    CS: TRTLCriticalSection;
    Shared: Integer;
  public
    FList: PItemList;
    procedure CopyItemsTo(Coll: TColl);
    function Copy: Pointer; override;
    function CopyItem(AItem: Pointer): Pointer; virtual;
    procedure DoInit(ALimit, ADelta: Integer);
    constructor Create;
    destructor Destroy; override;
    function At(Index: Integer): Pointer;
    procedure AtDelete(Index: Integer);
    procedure AtFree(Index: Integer);
    procedure AtInsert(Index: Integer; Item: Pointer);
    procedure AtPut(Index: Integer; Item: Pointer);
    procedure Delete(Item: Pointer);
    procedure DeleteAll;
    procedure FFree(Item: Pointer);
    procedure FreeAll;
    procedure FreeItem(Item: Pointer); virtual;
    function IndexOf(Item: Pointer): Integer; virtual;
    procedure Insert(Item: Pointer); virtual;
    procedure Add(Item: Pointer);
    procedure Pack;
    procedure SetCapacity(NewCapacity: Integer);
    procedure MoveTo(CurIndex, NewIndex: Integer);
    property Items[Idx: Integer]: Pointer read At write AtPut; default;
    property Count: Integer read FCount;
    property First: Pointer index 0 read At write AtPut;
    procedure ForEach(Proc: TForEachProc); virtual;
    procedure Sort(Compare: TListSortCompare);
    procedure Concat(AColl: TColl);
    procedure Enter;
    procedure Leave;
  end;

  TSortedColl = class(TColl)
  public
    Duplicates: Boolean;
    function Compare(Key1, Key2: Pointer): Integer; virtual; abstract;
    function KeyOf(Item: Pointer): Pointer; virtual;
    function IndexOf(Item: Pointer): Integer; override;
    procedure Insert(Item: Pointer); override;
    function Search(Key: Pointer; var Index: Integer): Boolean; virtual;
  end;

  { TStringColl object }

  TStringColl = class(TSortedColl)
  protected
    procedure SetString(Index: Integer; const Value: AnsiString);
    function GetString(Index: Integer): AnsiString;
  public
    function KeyOf(Item: Pointer): Pointer; override;
    procedure FreeItem(Item: Pointer); override;
    function Compare(Key1, Key2: Pointer): Integer; override;
    function CopyItem(AItem: Pointer): Pointer; override;
    function Copy: Pointer; override;
    procedure Ins(const S: AnsiString);
    procedure Ins0(const S: AnsiString);
    procedure Add(const S: AnsiString);
    procedure AtIns(Index: Integer; const Item: AnsiString);
    property Strings[Index: Integer]: AnsiString read GetString
      write SetString; default;
    function IdxOf(Item: AnsiString): Integer;
    procedure AppendTo(AColl: TStringColl);
    procedure Concat(AColl: TStringColl);
    procedure AddStrings(AStrings: TStringColl; ASort: Boolean);
    procedure Fill(const AStrs: array of AnsiString);
    function Found(const Str: AnsiString): Boolean;
    function FoundU(const Str: AnsiString): Boolean;
    function FoundUC(const Str: AnsiString): Boolean;
    procedure FillEnum(Str: AnsiString; Delim: AnsiChar; Sorted: Boolean);
    function LongString: AnsiString;
    function LongStringD(c: AnsiChar): AnsiString;
    procedure SetTextStr(const Value: AnsiString);
  end;

  { --- string routines }

function AddRightSpaces(const S: AnsiString; NumSpaces: Integer): AnsiString;
procedure AddStr(var S: AnsiString; c: AnsiChar);
procedure Add_Str(var S: ShortString; c: AnsiChar);
function CompareStr(const S1, S2: AnsiString): Integer; assembler;
function CopyLeft(const S: AnsiString; I: Integer): AnsiString;
procedure DelDoubles(const St: AnsiString; var Source: AnsiString);
procedure DelFC(var S: AnsiString);
procedure DelLC(var S: AnsiString);
function DelLeft(const S: AnsiString): AnsiString;
function DelRight(const S: AnsiString): AnsiString;
function DelSpaces(const S: AnsiString): AnsiString;
procedure DeleteLeft(var S: AnsiString; I: Integer);
function DigitsOnly(const AStr: AnsiString): Boolean;
procedure DisposeStr(P: PAnsiString);
function ExpandFileName(const FileName: AnsiString): AnsiString;
function ExtractFilePath(const FileName: AnsiString): AnsiString;
function ExtractDir(const S: AnsiString): AnsiString;
function ExtractFileRoot(const FileName: AnsiString): AnsiString;
function ExtractFileExt(const FileName: AnsiString): AnsiString;
function ExtractFileName(const FileName: AnsiString): AnsiString;
function ExtractFileDrive(const FileName: AnsiString): AnsiString;
function ExtractFileDir(const FileName: AnsiString): AnsiString;
procedure FSplit(const FName: AnsiString; var Path, Name, Ext: AnsiString);
procedure FillCharSet(const AStr: AnsiString; var CharSet: TCharSet);
function GetWrdStrictUC(var S, w: AnsiString): Boolean;
function GetWrdStrict(var S, w: AnsiString): Boolean;
function GetWrdD(var S, w: AnsiString): Boolean;
function GetWrdA(var S, w: AnsiString): Boolean;
function GetWrd(var S, w: AnsiString; c: AnsiChar): Boolean;
function Hex2(a: Byte): AnsiString;
function Hex4(a: Word): AnsiString;
function Hex8(a: DWORD): AnsiString;
function Int2Hex(a: Integer): AnsiString;
function Int2Str(L: Integer): AnsiString;
function ItoS(I: Integer): AnsiString;
function ItoSz(I, Width: Integer): AnsiString;
function LastDelimiter(const Delimiters, S: AnsiString): Integer;
function LowerCase(const S: AnsiString): AnsiString;
function MakeFullDir(const D, S: AnsiString): AnsiString;
function MakeNormName(const Path, Name: AnsiString): AnsiString;
function MonthE(m: Integer): AnsiString;
function NewStr(const S: AnsiString): PAnsiString;
function Replace(const Pattern, ReplaceString: AnsiString;
  var S: AnsiString): Boolean;
function StoI(const S: AnsiString): Integer;
function StrEnds(const S1, S2: AnsiString): Boolean;
function StrRight(const S: AnsiString; Num: Integer): AnsiString;
function UpperCase(const S: AnsiString): AnsiString;
function WipeChars(const AStr, AWipeChars: AnsiString): AnsiString;
function _Val(const S: AnsiString; var V: Integer): Boolean;

{ --- RFC Routines }

function ProcessQuotes(var S: AnsiString): Boolean;
function UnpackPchars(var S: AnsiString): Boolean;
function UnpackUchars(var S: AnsiString): Boolean;
function __alpha(c: AnsiChar): Boolean;
function __ctl(c: AnsiChar): Boolean;
function __digit(c: AnsiChar): Boolean;
function __extra(c: AnsiChar): Boolean;
function __national(c: AnsiChar): Boolean;
function __pchar(c: AnsiChar): Boolean;
function __reserved(c: AnsiChar): Boolean;
function __safe(c: AnsiChar): Boolean;
function __uchar(c: AnsiChar): Boolean;
function __unsafe(c: AnsiChar): Boolean;

{ --- Basic Routines }

function Buf2Str(const Buffer): AnsiString;
procedure Clear(var Buf; Count: Integer);
function CompareMem(P1, P2: Pointer; Length: Integer): Boolean; assembler;
procedure FreeObject(var O);
procedure LowerPrec(var a, B: Integer; Bits: Byte);
function MemEqu(const a, B; Sz: Integer): Boolean;
function MaxI(a, B: Integer): Integer;
function MinI(a, B: Integer): Integer;
function MaxD(a, B: DWORD): DWORD;
function MinD(a, B: DWORD): DWORD;
function NulSearch(const Buffer): Integer; assembler;
function NumBits(I: Integer): Integer; assembler;
procedure XAdd(var Critical, Normal); assembler;
procedure XChg(var Critical, Normal); assembler;

{ --- Win32 Events Extentions }

function CreateEvtA: THandle;
function CreateEvt(Initial: Boolean): THandle;
function SignaledEvt(id: THandle): Boolean;
function WaitEvt(const id: TWOHandleArray; Timeout: DWORD): DWORD;
function WaitEvtA(nCount: Integer; lpHandles: PWOHandleArray;
  Timeout: DWORD): DWORD;

{ --- Win32 API Hooks }

function ClearHandle(var Handle: THandle): Boolean;
procedure CloseHandles(const Handles: array of THandle);
function FileExists(const FName: AnsiString): Boolean;
function FindExecutable(FileName, Directory: PAnsiChar; Result: PAnsiChar)
  : HINST; stdcall;
function GetEnvVariable(const Name: AnsiString): AnsiString;
function GetFileNfo(const FName: AnsiString; var Info: TFileInfo;
  NeedAttr: Boolean): Boolean;
function GetFileNfoByHandle(Handle: THandle; var Info: TFileInfo): Boolean;
function ZeroHandle(var Handle: THandle): Boolean;

function _CreateFile(const FName: AnsiString; Mode: TCreateFileModeSet)
  : THandle;
function _CreateFileSecurity(const FName: AnsiString; Mode: TCreateFileModeSet;
  lpSecurityAttributes: PSecurityAttributes): THandle;
function _GetFileSize(const FName: AnsiString): DWORD;

function _MatchMaskBody(AName, AMask: AnsiString;
  SupportPercent: Boolean): Boolean;
function _MatchMask(const AName: AnsiString; AMask: AnsiString;
  SupportPercent: Boolean): Boolean;
function MatchMask(const AName, AMask: AnsiString): Boolean;

function SysErrorMsg(ErrorCode: DWORD): AnsiString;

{ --- Registry Routines }

function CreateRegKey(const AFName: AnsiString): HKey;
function OpenRegKeyEx(const AName: AnsiString; AMode: DWORD): HKey;
function OpenRegKey(const AName: AnsiString): DWORD;
function ReadRegBin(Key: DWORD; const rvn: AnsiString; Bin: Pointer;
  Sz: DWORD): Boolean;
function ReadRegInt(Key: DWORD; const AStrName: AnsiString): DWORD;
function ReadRegString(Key: DWORD; const AStrName: AnsiString): AnsiString;
function WriteRegBin(Key: DWORD; const rvn: AnsiString; Bin: Pointer;
  Sz: DWORD): Boolean;
function WriteRegInt(Key: DWORD; const AStrName: AnsiString;
  AValue: DWORD): Boolean;
function WriteRegString(Key: DWORD; const AStrName, AStr: AnsiString): Boolean;

{ --- Winsock tools }

function AddrInet(I: DWORD): AnsiString;
function GetHostNameByAddr(Addr: DWORD): AnsiString;
function Inet2addr(const S: AnsiString): DWORD;

{ --- Misc tools }

procedure GlobalFail;
function _LogOK(const Name: AnsiString; var Handle: THandle): Boolean;
procedure xBaseDone;
procedure xBaseInit;
procedure uCvtSetFileTime(T: DWORD; var L, H: DWORD);
function uCvtGetFileTime(L, H: DWORD): DWORD;
function uGetSystemTime: DWORD;
function Vl(const S: AnsiString): DWORD;
function VlH(const S: AnsiString): DWORD;
function StrAsg(const Src: AnsiString): AnsiString;

type
  TResetterThread = class(TThread)
    TimeToSleep, oSleep: DWORD;
    constructor Create;
    procedure Execute; override;
    destructor Destroy; override;
  end;

{$IFNDEF UNICODE}

  UnicodeString = WideString;
  RawByteString = AnsiString;
{$ENDIF}
function UnicodeStringToRawByteString(const w: UnicodeString; CP: Integer)
  : RawByteString;

var
  ResetterThread: TResetterThread;
  TimeZoneBias: Integer;
  SocketsColl: TColl;
  SocksCount: Integer;

const
  CServerVersion = '1.95';
  CServerProductName = 'TinyWeb';
  CServerName = CServerProductName + '/' + CServerVersion;
  CMB_FAILED = MB_APPLMODAL or MB_OK or MB_ICONSTOP;

implementation

/// /////////////////////////////////////////////////////////////////////
// //
// Time Routines                             //
// //
/// /////////////////////////////////////////////////////////////////////

const
  cTimeHi = 27111902;
  cTimeLo = -717324288;
  cSecScale = 10000000;
  cAgeScale = 10000;

{$IFDEF FPC}
{$ASMMODE Intel}
{$ENDIF}

function uCvtGetFileTime(L, H: DWORD): DWORD; assembler;
asm
  mov ecx, cSecScale
  sub eax, cTimeLo
  sbb edx, cTimeHi
  jns @@ns
  mov eax, 0
  jmp @@ok
@@ns:
  div ecx
  test eax, eax
  jns @@ok
  mov eax, MaxInt
@@ok:
end;

function uCvtGetFileAge(L, H: DWORD): DWORD; assembler;
asm
  mov ecx, cAgeScale
  div ecx
end;

procedure uCvtSetFileTime(T: DWORD; var L, H: DWORD); assembler;
asm
  push edx
  push ebx
  mov  ebx, cSecScale
  mul  ebx
  pop  ebx
  add  eax, cTimeLo
  adc  edx, cTimeHi
  mov  [ecx], edx
  pop  edx
  mov  [edx], eax
end;

procedure uNix2WinTime(I: DWORD; var T: TSystemTime);
var
  F: TFileTime;
begin
  FillChar(F, SizeOf(F), 0);
  uCvtSetFileTime(I, F.dwLowDateTime, F.dwHighDateTime);
  FileTimeToSystemTime(F, T);
end;

function uWin2NixTime(const T: TSystemTime): DWORD;
var
  F: TFileTime;
begin
  FillChar(F, SizeOf(F), 0);
  SystemTimeToFileTime(T, F);
  Result := uCvtGetFileTime(F.dwLowDateTime, F.dwHighDateTime);
end;

function uGetSystemTime: DWORD;
var
  T: TFileTime;
begin
  FillChar(T, SizeOf(T), 0);
  GetSystemTimeAsFileTime(T);
  Result := uCvtGetFileTime(T.dwLowDateTime, T.dwHighDateTime);
end;

function uSetFileTimeByHandle(Handle: THandle; uTime: DWORD): Boolean;
var
  F: TFileTime;
begin
  FillChar(F, SizeOf(F), 0);
  uCvtSetFileTime(uTime, F.dwLowDateTime, F.dwHighDateTime);
  Result := SetFileTime(Handle, nil, nil, @F);
end;

function uSetFileTime(const FName: AnsiString; uTime: DWORD): Boolean;
var
  Handle: THandle;
begin
  Result := False;
  Handle := _CreateFile(FName, [cWrite, cExisting]);
  if Handle = INVALID_HANDLE_VALUE then
    Exit;
  Result := uSetFileTimeByHandle(Handle, uTime);
  CloseHandle(Handle);
end;

procedure CvtFD(const wf: TWin32FindDataA; var FindData: TuFindData);
begin
  FindData.Info.Attr := wf.dwFileAttributes;
  FindData.Info.Time := uCvtGetFileTime(wf.ftLastWriteTime.dwLowDateTime,
    wf.ftLastWriteTime.dwHighDateTime);
  FindData.Info.Size := wf.nFileSizeLow;
  FindData.FName := Buf2Str(wf.cFileName);
end;

function uFindFirst(const FName: AnsiString; var FindData: TuFindData): THandle;
var
  wf: TWin32FindDataA;
begin
  if FName = '' then
  begin
    Result := INVALID_HANDLE_VALUE
  end
  else
  begin
    FillChar(wf, SizeOf(wf), 0);
    Result := FindFirstFileA(@(FName[1]), wf);
    if Result <> INVALID_HANDLE_VALUE then
      CvtFD(wf, FindData);
  end;
end;

function uFindNext(Handle: THandle; var FindData: TuFindData): Boolean;
var
  wf: TWin32FindDataA;
begin
  FillChar(wf, SizeOf(wf), 0);
  Result := FindNextFileA(Handle, wf);
  if Result then
    CvtFD(wf, FindData);
end;

function uFindClose(Handle: THandle): Boolean;
begin
  Result := Windows.FindClose(Handle);
end;

/// /////////////////////////////////////////////////////////////////////
// //
// AnsiString Routines                            //
// //
/// /////////////////////////////////////////////////////////////////////

function IsWild(const S: AnsiString): Boolean;
var
  a, Q: AnsiChar;
begin
  a := '*';
  Q := '?';
  Result := (Pos(a, S) > 0) or (Pos(Q, S) > 0);
end;

function TrimZeros(S: AnsiString): AnsiString;
var
  I, J: Integer;
begin
  I := Length(S);
  while (I > 0) and (S[I] <= ' ') do
    Dec(I);
  J := 1;
  while (J < I) and ((S[J] <= ' ') or (S[J] = '0')) do
    Inc(J);
  TrimZeros := Copy(S, J, (I - J) + 1);
end;

function BothKVC(const S: AnsiString): Boolean;
begin
  Result := (Copy(S, 1, 1) = '"') and (Copy(S, Length(S), 1) = '"');
end;

function AddRightSpaces(const S: AnsiString; NumSpaces: Integer): AnsiString;
begin
  Result := '';
  SetLength(Result, NumSpaces);
  FillChar(Result[1], NumSpaces, ' ');
  Move(S[1], Result[1], MinI(NumSpaces, Length(S)));
end;

function Hex2(a: Byte): AnsiString;
begin
  Result := '';
  SetLength(Result, 2);
  Result[1] := rrLoHexChar[a shr 4];
  Result[2] := rrLoHexChar[a and $F];
end;

function Hex4(a: Word): AnsiString;
var
  I: Integer;
begin
  Result := '';
  SetLength(Result, 4);
  for I := 0 to 3 do
  begin
    Result[4 - I] := rrLoHexChar[a and $F];
    a := a shr 4;
  end;
end;

function Hex8(a: DWORD): AnsiString;
var
  I: DWORD;
begin
  Result := '';
  SetLength(Result, 8);
  for I := 0 to 7 do
  begin
    Result[8 - I] := rrLoHexChar[a and $F];
    a := a shr 4;
  end;
end;

function Int2Hex(a: Integer): AnsiString;
begin
  Result := Hex8(a);
  while (Length(Result) > 1) and (Result[1] = '0') do
    DelFC(Result);
end;

function MakeFullDir(const D, S: AnsiString): AnsiString;
var
  SC: AnsiChar;
begin
  SC := ':';
  if (Pos(SC, S) > 0) or (Copy(S, 1, 2) = '\\') then
    Result := S
  else if Copy(S, 1, 1) = '\' then
    Result := MakeNormName(Copy(D, 1, Pos(SC, D)), Copy(S, 2, Length(S) - 1))
  else
    Result := MakeNormName(D, S);
end;

function ExtractDir(const S: AnsiString): AnsiString;
var
  I: Integer;
begin
  Result := S;
  I := Length(S);
  if (I > 3) and (S[I] = '\') then
    DelLC(Result);
end;

function MakeNormName(const Path, Name: AnsiString): AnsiString;
begin
  Result := Path;
  if (Result <> '') and (Result[Length(Result)] <> '\') then
    AddStr(Result, '\');
  Result := Result + Name;
end;

procedure AddStr(var S: AnsiString; c: AnsiChar);
begin
  S := S + c;
end;

procedure Add_Str(var S: ShortString; c: AnsiChar);
var
  sl: Byte absolute S;
begin
  Inc(sl);
  S[sl] := c;
end;

procedure FSplit(const FName: AnsiString; var Path, Name, Ext: AnsiString);
type
  TStep = (sExt, sName, sPath);
var
  Step: TStep;
  I: Integer;
  c, D: AnsiChar;
begin
  D := '.';
  I := Length(FName);
  if Pos(D, FName) = 0 then
    Step := sName
  else
    Step := sExt;
  Path := '';
  Name := '';
  Ext := '';
  while I > 0 do
  begin
    c := FName[I];
    Dec(I);
    case Step of
      sExt:
        case c of
          '.':
            begin
              Ext := c + Ext;
              Inc(Step);
            end;
          '\', ':':
            begin
              Name := Ext;
              Ext := '';
              Path := c;
              Step := sPath;
            end;
        else
          Ext := c + Ext;
        end;
      sName:
        if (c = '\') or (c = ':') then
        begin
          Path := c;
          Inc(Step)
        end
        else
          Name := c + Name;
      sPath:
        Path := c + Path;
    end;
  end;
end;

function Replace(const Pattern, ReplaceString: AnsiString;
  var S: AnsiString): Boolean;
var
  I, J: Integer;
  LP, LR: Integer;
begin
  Result := False;
  J := 1;
  LP := Length(Pattern);
  LR := Length(ReplaceString);
  repeat
    I := Pos(Pattern, CopyLeft(S, J));
    if I > 0 then
    begin
      Delete(S, J + I - 1, LP);
      Insert(ReplaceString, S, J + I - 1);
      Result := True;
    end;
    Inc(J, I + LR - 1);
  until I = 0;
end;

procedure DelDoubles(const St: AnsiString; var Source: AnsiString);
var
  I: Integer;
begin
  repeat
    I := Pos(St, Source);
    if I = 0 then
      Break;
    Delete(Source, I, 1);
  until False;
end;

function ItoS(I: Integer): AnsiString;
begin
  Str(I, Result);
end;

function ItoSz(I, Width: Integer): AnsiString;
begin
  Result := ItoS(I);
  while Length(Result) < Width do
    Result := '0' + Result;
end;

function DelLeft(const S: AnsiString): AnsiString;
var
  I, L: Integer;
begin
  I := 1;
  L := Length(S);
  while I <= L do
  begin
    case S[I] of
      #9, ' ':
        ;
    else
      Break
    end;
    Inc(I);
  end;
  Result := Copy(S, I, L + 1 - I);
end;

function DelRight(const S: AnsiString): AnsiString;
var
  I: Integer;
begin
  I := Length(S);
  while I > 0 do
  begin
    case S[I] of
      #9, ' ':
        ;
    else
      Break
    end;
    Dec(I);
  end;
  Result := Copy(S, 1, I);
end;

function DelSpaces(const S: AnsiString): AnsiString;
begin
  Result := DelLeft(DelRight(S));
end;

procedure DelFC(var S: AnsiString);
begin
  Delete(S, 1, 1);
end;

procedure DelLC(var S: AnsiString);
var
  L: Integer;
begin
  L := Length(S);
  case L of
    0:
      ;
    1:
      S := '';
  else
    SetLength(S, L - 1);
  end;
end;

function Int2Str(L: Integer): AnsiString;
var
  I: Integer;
begin
  Result := ItoS(L);
  I := Length(Result) - 2;
  while I > 1 do
  begin
    Insert(',' { ThousandSeparator } , Result, I);
    Dec(I, 3);
  end;
end;

function ExtractFileRoot(const FileName: AnsiString): AnsiString;
var
  SC: AnsiChar;
begin
  SC := ':';
  Result := Copy(FileName, 1, Pos(SC, FileName) + 1);
end;

function WipeChars(const AStr, AWipeChars: AnsiString): AnsiString;
var
  I, J: Integer;
begin
  Result := '';
  J := Length(AStr);
  for I := 1 to J do
    if Pos(AStr[I], AWipeChars) = 0 then
      AddStr(Result, AStr[I]);
end;

procedure FillCharSet(const AStr: AnsiString; var CharSet: TCharSet);
var
  I: Integer;
begin
  CharSet := [];
  for I := 1 to Length(AStr) do
    Include(CharSet, AStr[I]);
end;

function DigitsOnly(const AStr: AnsiString): Boolean;
var
  I: Integer;
begin
  Result := False;
  if AStr = '' then
    Exit;
  for I := 1 to Length(AStr) do
    if not __digit(AStr[I]) then
      Exit;
  Result := True;
end;

function GetWrdD(var S, w: AnsiString): Boolean;
begin
  Result := False;
  w := '';
  if S = '' then
    Exit;
  while (Length(S) > 0) and ((S[1] < '0') or (S[1] > '9')) do
  begin
    DelFC(S)
  end;
  while (Length(S) > 0) and (S[1] >= '0') and (S[1] <= '9') do
  begin
    w := w + S[1];
    DelFC(S)
  end;
  DelFC(S);
  Result := True;
end;

function GetWrdA(var S, w: AnsiString): Boolean;
begin
  Result := False;
  w := '';
  if S = '' then
    Exit;
  while (Length(S) > 0) and ((UpCase(S[1]) < 'A') or (UpCase(S[1]) > 'Z')) do
  begin
    DelFC(S)
  end;
  while (Length(S) > 0) and (UpCase(S[1]) >= 'A') and (UpCase(S[1]) <= 'Z') do
  begin
    w := w + S[1];
    DelFC(S)
  end;
  DelFC(S);
  Result := True;
end;

function GetWrd(var S, w: AnsiString; c: AnsiChar): Boolean;
const
  Space: AnsiChar = ' ';
var
  I, J: Integer;
begin
  Result := False;
  w := '';
  if S = '' then
    Exit;
  if (c = Space) and (Pos(Space, S) > 0) then
    S := DelSpaces(S);
  J := 0;
  for I := 1 to Length(S) do
  begin
    if S[I] = c then
      Break;
    Inc(J);
  end;
  w := Copy(S, 1, J);
  Delete(S, 1, J);
  Result := S = '';
  if not Result then
    Delete(S, 1, 1);
end;

function GetWrdStrict(var S, w: AnsiString): Boolean;
var
  I, J: Integer;
begin
  Result := False;
  w := '';
  if S = '' then
    Exit;
  J := 0;
  for I := 1 to Length(S) do
  begin
    if S[I] = ' ' then
      Break;
    Inc(J);
  end;
  w := Copy(S, 1, J);
  Delete(S, 1, J);
  Result := S = '';
  if not Result then
    Delete(S, 1, 1);
end;

function GetWrdStrictUC(var S, w: AnsiString): Boolean;
var
  I, J: Integer;
begin
  Result := False;
  w := '';
  if S = '' then
    Exit;
  J := 0;
  for I := 1 to Length(S) do
  begin
    if S[I] = ' ' then
      Break;
    Inc(J);
  end;
  w := UpperCase(Copy(S, 1, J));
  Delete(S, 1, J);
  Result := S = '';
  if not Result then
    Delete(S, 1, 1);
end;

function StrRight(const S: AnsiString; Num: Integer): AnsiString;
begin
  Result := Copy(S, Length(S) - Num + 1, Num);
end;

function StrEnds(const S1, S2: AnsiString): Boolean;
begin
  Result := StrRight(S1, Length(S2)) = S2;
end;

function CopyLeft(const S: AnsiString; I: Integer): AnsiString;
begin
  Result := Copy(S, I, Length(S) - I + 1);
end;

procedure DeleteLeft(var S: AnsiString; I: Integer);
begin
  Delete(S, I, Length(S) - I + 1);
end;

/// /////////////////////////////////////////////////////////////////////
// //
// Basic Routines                            //
// //
/// /////////////////////////////////////////////////////////////////////

procedure Clear(var Buf; Count: Integer);
begin
  FillChar(Buf, Count, 0);
end;

function MemEqu(const a, B; Sz: Integer): Boolean; assembler;
asm
  push  ebx
  xchg  eax, ebx
  jmp   @1

@0: inc   edx
@1: mov   al, [ebx]
  inc   ebx
  cmp   al, [edx]
  jne   @@Wrong
  dec   ecx
  jnz   @0

  mov   eax, 1
  jmp   @@End
@@Wrong:
  mov   eax, 0
@@End:
  pop   ebx
end;

function MaxI(a, B: Integer): Integer; assembler;
asm
  cmp  eax, edx
  jg   @@g
  xchg eax, edx
@@g:
end;

function MinI(a, B: Integer): Integer; assembler;
asm
  cmp  eax, edx
  jl   @@l
  xchg eax, edx
@@l:
end;

function MaxD(a, B: DWORD): DWORD; assembler;
asm
  cmp  eax, edx
  ja   @@a
  xchg eax, edx
@@a:
end;

function MinD(a, B: DWORD): DWORD; assembler;
asm
  cmp  eax, edx
  jb   @@b
  xchg eax, edx
@@b:
end;

procedure XChg(var Critical, Normal); assembler;
asm
  mov  ecx, [edx]
  xchg [eax], ecx
  mov  [edx], ecx
end;

function NulSearch(const Buffer): Integer; assembler;
asm
  CLD
  PUSH    EDI
  MOV     EDI, Buffer
  XOR     AL,  AL
  MOV     ECX, -1
  REPNE   SCASB
  XCHG    EAX,ECX
  NOT     EAX
  DEC     EAX
  POP     EDI
end;

function Buf2Str(const Buffer): AnsiString;
var
  I: Integer;
begin
  I := NulSearch(Buffer);
  if I = 0 then
    Result := ''
  else
  begin
    SetLength(Result, I);
    Move(Buffer, Result[1], I);
  end;
end;

procedure LowerPrec(var a, B: Integer; Bits: Byte);
var
  c: ShortInt;
begin
  c := MaxI(NumBits(a), NumBits(B)) - Bits;
  if c <= 0 then
    Exit;
  a := a shr c;
  B := B shr c;
end;

/// /////////////////////////////////////////////////////////////////////
// //
// Win32 Events Extentions                       //
// //
/// /////////////////////////////////////////////////////////////////////

function CreateEvtA: THandle;
begin
  Result := CreateEvent(nil, False, False, nil);
end;

function CreateEvt(Initial: Boolean): THandle;
begin
  CreateEvt := CreateEvent(nil, // address of security attributes
    True, // flag for manual-reset event
    Initial, // flag for initial state
    nil); // address of event-object name
end;

function WaitEvtA(nCount: Integer; lpHandles: PWOHandleArray;
  Timeout: DWORD): DWORD;
begin
  if Timeout = High(Timeout) then
    Timeout := INFINITE;
  if nCount = 1 then
    Result := WaitForSingleObject(lpHandles^[0], Timeout)
  else
    Result := WaitForMultipleObjects(nCount, lpHandles, False, Timeout);
end;

function WaitEvt(const id: TWOHandleArray; Timeout: DWORD): DWORD;
begin
  Result := WaitEvtA(High(id) + 1, @id, Timeout);
end;

function SignaledEvt(id: THandle): Boolean;
begin
  SignaledEvt := WaitForSingleObject(id, 0) = id;
end;

/// /////////////////////////////////////////////////////////////////////
// //
// Win32 API Hooks                               //
// //
/// /////////////////////////////////////////////////////////////////////

procedure CloseHandles(const Handles: array of THandle);
var
  I: Integer;
begin
  for I := 0 to High(Handles) do
    CloseHandle(Handles[I]);
end;

function FileExists(const FName: AnsiString): Boolean;
var
  Handle: THandle;
begin
  Result := False;
  Handle := _CreateFile(FName, [cRead, cShareAllowWrite]);
  if Handle = INVALID_HANDLE_VALUE then
    Exit;
  Result := ZeroHandle(Handle);
end;

function GetFileNfo(const FName: AnsiString; var Info: TFileInfo;
  NeedAttr: Boolean): Boolean;
var
  Handle: THandle;
begin
  Result := False;
  Handle := _CreateFile(FName, [cRead, cShareAllowWrite]);
  if Handle = INVALID_HANDLE_VALUE then
    Exit;
  Result := GetFileNfoByHandle(Handle, Info);
  CloseHandle(Handle);
  if NeedAttr and Result and (Info.Attr = INVALID_FILE_ATTRIBUTES) and
    (FName <> '') then
    Result := GetFileAttributesA(@(FName[1])) <> INVALID_FILE_ATTRIBUTES;
end;

function GetFileNfoByHandle(Handle: THandle; var Info: TFileInfo): Boolean;
var
  I: TByHandleFileInformation;
begin
  Result := False;
  if Handle = INVALID_HANDLE_VALUE then
    Exit;
  I.dwFileAttributes := INVALID_FILE_ATTRIBUTES;
  I.nFileSizeLow := GetFileSize(Handle, nil);
  Result := (I.nFileSizeLow <> INVALID_FILE_SIZE) and
    GetFileTime(Handle, nil, nil, @I.ftLastWriteTime);
  if not Result then
    Exit;
  Info.Size := I.nFileSizeLow;
  Info.Attr := I.dwFileAttributes;
  Info.Time := uCvtGetFileTime(I.ftLastWriteTime.dwLowDateTime,
    I.ftLastWriteTime.dwHighDateTime);
  Result := True;
end;

function ClearHandle(var Handle: THandle): Boolean;
begin
  if Handle = INVALID_HANDLE_VALUE then
    Result := False
  else
  begin
    Result := CloseHandle(Handle);
    Handle := INVALID_HANDLE_VALUE;
  end;
end;

function ZeroHandle(var Handle: THandle): Boolean;
begin
  if (Handle = INVALID_HANDLE_VALUE) or (Handle = 0) then
    Result := False
  else
  begin
    Result := CloseHandle(Handle);
    Handle := 0;
  end;
end;

procedure _PostMessage(a, B, c, D: DWORD);
begin
  if not PostMessage(a, B, c, D) then
    GlobalFail;
end;

function _CreateFile(const FName: AnsiString; Mode: TCreateFileModeSet)
  : THandle;
begin
  Result := _CreateFileSecurity(FName, Mode, nil);
end;

function _CreateFileSecurity(const FName: AnsiString; Mode: TCreateFileModeSet;
  lpSecurityAttributes: PSecurityAttributes): THandle;
var
  Access, Share, Disp, Flags: DWORD;

const
  NumDispModes = 5;
DispArr:
array [1 .. NumDispModes] of record w: Boolean; { Write }
N:
Boolean; { EnsureNew }
T:
Boolean; { Truncate }
D:
DWORD; { Disp }
end
= ((w: False; N: False; T: False; D: OPEN_EXISTING), (w: True; N: False;
  T: False; D: OPEN_ALWAYS), (w: True; N: True; T: False; D: CREATE_NEW),
  (w: True; N: False; T: True; D: CREATE_ALWAYS), (w: True; N: True; T: True;
  D: TRUNCATE_EXISTING));
begin
  if FName = '' then
  begin
    Result := INVALID_HANDLE_VALUE;
    Exit;
  end;

  // Prepare Disp & Flags

  Flags := FILE_ATTRIBUTE_NORMAL;
  Access := 0;
  Share := 0;
  Disp := 0;

  if cFlag in Mode then
  begin
    Disp := CREATE_NEW;
    Flags := Flags or FILE_FLAG_DELETE_ON_CLOSE
  end
  else
  begin

    if cTruncate in Mode then
      Mode := Mode + [cWrite];

    if cExisting in Mode then
      Disp := OPEN_EXISTING
    else
    begin
      if cWrite in Mode then
        Flags := FILE_ATTRIBUTE_ARCHIVE;
      repeat
        Inc(Disp);
        if Disp > NumDispModes then
          GlobalFail;
        with DispArr[Disp] do
          if (w = (cWrite in Mode)) and (N = (cEnsureNew in Mode)) and
            (T = (cTruncate in Mode)) then
          begin
            Disp := D;
            Break
          end;
      until False;

    end;

    if cOverlapped in Mode then
      Flags := Flags or FILE_FLAG_OVERLAPPED;
    if cRandomAccess in Mode then
      Flags := Flags or FILE_FLAG_RANDOM_ACCESS;
    if cSequentialScan in Mode then
      Flags := Flags or FILE_FLAG_SEQUENTIAL_SCAN;
    if cDeleteOnClose in Mode then
      Flags := Flags or FILE_FLAG_DELETE_ON_CLOSE;


    // Prepare 'Access' and 'Share'

    if cShareAllowWrite in Mode then
      Share := FILE_SHARE_WRITE;
    if cRead in Mode then
    begin
      Access := Access or GENERIC_READ;
      Share := Share or FILE_SHARE_READ
    end;
    if cWrite in Mode then
    begin
      Access := Access or GENERIC_WRITE;
      Share := Share or FILE_SHARE_READ
    end;
    if cShareDenyRead in Mode then
      Share := Share and not FILE_SHARE_READ;
  end;

  Result := CreateFileA(@(FName[1]), Access, Share, lpSecurityAttributes, Disp,
    Flags, 0);
end;

function _GetFileSize(const FName: AnsiString): DWORD;
var
  H: DWORD;
begin
  Result := INVALID_FILE_SIZE;
  H := _CreateFile(FName, [cRead]);
  if H = INVALID_HANDLE_VALUE then
    Exit;
  Result := GetFileSize(H, nil);
  CloseHandle(H);
end;

function WindowsDirectory: AnsiString;
begin
  Result := '';
  SetLength(Result, MAX_PATH);
  GetWindowsDirectoryA(@(Result[1]), MAX_PATH);
  SetLength(Result, NulSearch(Result[1]));
end;

/// /////////////////////////////////////////////////////////////////////
// //
// Registry Routines                             //
// //
/// /////////////////////////////////////////////////////////////////////

function OpenRegKeyEx(const AName: AnsiString; AMode: DWORD): HKey;
begin
  if AName = '' then
  begin
    Result := INVALID_REGISTRY_KEY;
    Exit;
  end;
  if RegOpenKeyExA(HKEY_LOCAL_MACHINE, // handle of an open key
    @(AName[1]), // subkey name
    0, // Reserved
    AMode, Result) <> ERROR_SUCCESS then
    Result := INVALID_REGISTRY_KEY;
end;

function OpenRegKey(const AName: AnsiString): DWORD;
begin
  Result := OpenRegKeyEx(AName, KEY_QUERY_VALUE);
end;

function CreateRegKey(const AFName: AnsiString): HKey;
var
  Disp: DWORD;
begin
  if AFName = '' then
  begin
    Result := INVALID_REGISTRY_KEY;
    Exit;
  end;
  if RegCreateKeyExA(HKEY_LOCAL_MACHINE, // handle of an open key
    @(AFName[1]), // subkey name
    0, // reserved, must be zero
    nil, // address of class AnsiString
    REG_OPTION_NON_VOLATILE, // options flag
    KEY_WRITE, // desired security access
    nil, // security attributes
    Result, // address of buffer for opened handle
    @Disp // address of disposition value buffer
    ) <> ERROR_SUCCESS then
  begin
    Result := INVALID_REGISTRY_KEY;
  end;

end;

function WriteRegString(Key: DWORD; const AStrName, AStr: AnsiString): Boolean;
begin
  if (AStrName = '') or (AStr = '') then
  begin
    Result := False;
  end
  else
  begin
    Result := RegSetValueExA(Key, @(AStrName[1]), 0, REG_SZ, @(AStr[1]),
      Length(AStr) + 1) = ERROR_SUCCESS;
  end;
end;

function ReadRegString(Key: DWORD; const AStrName: AnsiString): AnsiString;
var
  L, T, e: DWORD;
  z: AnsiString;
  PDataBuf: PAnsiChar;
begin
  L := 250;
  z := '';
  SetLength(z, L + 1);
  PDataBuf := @(z[1]);
  T := REG_SZ;
  e := RegQueryValueExA(Key, // handle of key to query
    PAnsiChar(AStrName), // value to query
    nil, // reserved
    @T, // value type
    PByte(PDataBuf), // data buffer
    @L // buffer size
    );
  if e <> ERROR_SUCCESS then
    Result := ''
  else
  begin
    Result := Copy(z, 1, NulSearch(z[1]));
  end;
end;

function WriteRegInt(Key: DWORD; const AStrName: AnsiString;
  AValue: DWORD): Boolean;
begin
  if AStrName = '' then
  begin
    Result := False;
  end
  else
  begin
    Result := RegSetValueExA(Key, @(AStrName[1]), 0, REG_DWORD, @AValue,
      SizeOf(AValue)) = ERROR_SUCCESS;
  end;
end;

function ReadRegInt(Key: DWORD; const AStrName: AnsiString): DWORD;
var
  T, e, S: DWORD;
  B: Integer;
  PDataBuf: PInteger;
begin
  if AStrName = '' then
  begin
    Result := INVALID_REGISTRY_KEY;
    Exit;
  end;
  T := REG_DWORD;;
  S := SizeOf(B);
  PDataBuf := @B;
  e := RegQueryValueExA(Key, // handle of key to query
    @(AStrName[1]), // value to query
    nil, // reserved
    @T, // value type
    PByte(PDataBuf), // data buffer
    @S // buffer size
    );
  if e <> ERROR_SUCCESS then
    Result := INVALID_REGISTRY_KEY
  else
    Result := B;
end;

function WriteRegBin(Key: DWORD; const rvn: AnsiString; Bin: Pointer;
  Sz: DWORD): Boolean;
begin
  if rvn = '' then
  begin
    Result := False;
  end
  else
  begin
    Result := RegSetValueExA(Key, @(rvn[1]), 0, REG_BINARY, Bin, Sz)
      = ERROR_SUCCESS;
  end;
end;

function ReadRegBin(Key: DWORD; const rvn: AnsiString; Bin: Pointer;
  Sz: DWORD): Boolean;
var
  T, e, S: DWORD;
begin
  if rvn = '' then
  begin
    Result := False;
    Exit;
  end;
  T := REG_BINARY;;
  S := Sz;
  e := RegQueryValueExA(Key, // handle of key to query
    @(rvn[1]), // value to query
    nil, // reserved
    @T, // value type
    Bin, // data buffer
    @S // buffer size
    );
  Result := e = ERROR_SUCCESS;
end;

/// /////////////////////////////////////////////////////////////////////
// //
// Objects                                //
// //
/// /////////////////////////////////////////////////////////////////////

function SysErrorMsg(ErrorCode: DWORD): AnsiString;
var
  Len: Integer;
  Buffer: array [0 .. 255] of AnsiChar;
begin
  Len := FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM or
    FORMAT_MESSAGE_ARGUMENT_ARRAY, nil, ErrorCode, 0, Buffer,
    SizeOf(Buffer), nil);
  while (Len > 0) and (Buffer[Len - 1] in [#0 .. #32, '.']) do
    Dec(Len);
  SetString(Result, Buffer, Len);
end;

procedure QuickSort(SortList: PItemList; L, R: Integer;
  SCompare: TListSortCompare);
var
  I, J: Integer;
  P, T: Pointer;
begin
  repeat
    I := L;
    J := R;
    P := SortList^[(L + R) shr 1];
    repeat
      while SCompare(SortList^[I], P) < 0 do
        Inc(I);
      while SCompare(SortList^[J], P) > 0 do
        Dec(J);
      if I <= J then
      begin
        T := SortList^[I];
        SortList^[I] := SortList^[J];
        SortList^[J] := T;
        Inc(I);
        Dec(J);
      end;
    until I > J;
    if L < J then
      QuickSort(SortList, L, J, SCompare);
    L := I;
  until I >= R;
end;

{ ---- TColl ---- }

procedure TColl.Sort(Compare: TListSortCompare);
begin
  if (FList <> nil) and (Count > 0) then
    QuickSort(FList, 0, Count - 1, Compare);
end;

function TColl.Copy: Pointer;
begin
  Result := TColl.Create;
  CopyItemsTo(TColl(Result));
end;

procedure TColl.CopyItemsTo(Coll: TColl);
var
  I: Integer;
begin
  Coll.FreeAll;
  for I := 0 to Count - 1 do
    Coll.AtInsert(Coll.Count, CopyItem(At(I)));
end;

function TColl.CopyItem(AItem: Pointer): Pointer;
begin
  Result := TAdvCpObject(AItem).Copy;
end;

procedure TColl.Concat(AColl: TColl);
var
  I: Integer;
begin
  for I := 0 to AColl.Count - 1 do
    Insert(AColl[I]);
  AColl.DeleteAll;
end;

procedure TColl.Enter;
var
  J: Integer;
begin
  J := 1;
  XChg(Shared, J);
  if J = 0 then
    InitializeCriticalSection(CS);
  EnterCriticalSection(CS);
end;

procedure TColl.Leave;
begin
  LeaveCriticalSection(CS);
end;

procedure TColl.ForEach(Proc: TForEachProc);
var
  I: Integer;
begin
  for I := 0 to Count - 1 do
    Proc(FList^[I]);
end;

constructor TColl.Create;
begin
  inherited Create;
  DoInit(32, 64);
end;

procedure TColl.DoInit(ALimit, ADelta: Integer);
begin
  FList := nil;
  FCount := 0;
  FCapacity := 0;
  FDelta := ADelta;
  SetCapacity(ALimit);
end;

destructor TColl.Destroy;
begin
  if Shared = 1 then
    DeleteCriticalSection(CS);
  FreeAll;
  SetCapacity(0);
  inherited Destroy;
end;

function TColl.At(Index: Integer): Pointer;
begin
  if (Index < 0) or (Index >= FCount) then
    GlobalFail;
  Result := FList^[Index];
end;

procedure TColl.AtDelete(Index: Integer);
begin
  if (Index < 0) or (Index >= FCount) then
    GlobalFail;
  Dec(FCount);
  if Index < FCount then
    System.Move(FList^[Index + 1], FList^[Index],
      (FCount - Index) * SizeOf(Pointer));
end;

procedure TColl.AtFree(Index: Integer);
var
  Item: Pointer;
begin
  Item := At(Index);
  AtDelete(Index);
  FreeItem(Item);
end;

procedure TColl.AtInsert(Index: Integer; Item: Pointer);
begin
  if (Index < 0) or (Index > FCount) then
    GlobalFail;
  if FCount = FCapacity then
    SetCapacity(FCapacity + FDelta);
  if Index < FCount then
    System.Move(FList^[Index], FList^[Index + 1],
      (FCount - Index) * SizeOf(Pointer));
  FList^[Index] := Item;
  Inc(FCount);
end;

procedure TColl.AtPut(Index: Integer; Item: Pointer);
begin
  if (Index < 0) or (Index >= FCount) then
    GlobalFail;
  FList^[Index] := Item;
end;

procedure TColl.Delete(Item: Pointer);
begin
  AtDelete(IndexOf(Item));
end;

procedure TColl.DeleteAll;
begin
  FCount := 0;
end;

procedure TColl.FFree(Item: Pointer);
begin
  Delete(Item);
  FreeItem(Item);
end;

procedure TColl.FreeAll;
var
  I: Integer;
begin
  for I := 0 to FCount - 1 do
    FreeItem(At(I));
  FCount := 0;
end;

procedure TColl.FreeItem(Item: Pointer);
begin
  TObject(Item).Free;
end;

function TColl.IndexOf(Item: Pointer): Integer;
begin
  Result := 0;
  while (Result < FCount) and (FList^[Result] <> Item) do
    Inc(Result);
  if Result = FCount then
    Result := -1;
end;

procedure TColl.Insert(Item: Pointer);
begin
  AtInsert(FCount, Item);
end;

procedure TColl.Add(Item: Pointer);
begin
  AtInsert(FCount, Item);
end;

procedure TColl.Pack;
var
  I: Integer;
begin
  for I := FCount - 1 downto 0 do
    if Items[I] = nil then
      AtDelete(I);
end;

procedure TColl.SetCapacity(NewCapacity: Integer);
begin
  if (NewCapacity < FCount) or (NewCapacity > MaxCollSize) then
    GlobalFail;
  if NewCapacity <> FCapacity then
  begin
    ReallocMem(FList, NewCapacity * SizeOf(Pointer));
    FCapacity := NewCapacity;
  end;
end;

procedure TColl.MoveTo(CurIndex, NewIndex: Integer);
var
  Item: Pointer;
begin
  if CurIndex <> NewIndex then
  begin
    if (NewIndex < 0) or (NewIndex >= FCount) then
      GlobalFail;
    Item := FList^[CurIndex];
    AtDelete(CurIndex);
    AtInsert(NewIndex, Item);
  end;
end;

{ TSortedColl }

function TSortedColl.KeyOf(Item: Pointer): Pointer;
begin
  Result := Item;
end;

function TSortedColl.IndexOf(Item: Pointer): Integer;
var
  I: Integer;
begin
  IndexOf := -1;
  I := -1;
  if Search(KeyOf(Item), I) then
  begin
    if Duplicates then
      while (I < Count) and (Item <> FList^[I]) do
        Inc(I);
    if I < Count then
      IndexOf := I;
  end;
end;

procedure TSortedColl.Insert(Item: Pointer);
var
  I: Integer;
begin
  I := -1;
  if not Search(KeyOf(Item), I) or Duplicates then
    AtInsert(I, Item);
end;

function TSortedColl.Search(Key: Pointer; var Index: Integer): Boolean;
var
  L, H, I, c: Integer;
begin
  Search := False;
  L := 0;
  H := Count - 1;
  while L <= H do
  begin
    I := (L + H) shr 1;
    c := Compare(KeyOf(FList^[I]), Key);
    if c < 0 then
      L := I + 1
    else
    begin
      H := I - 1;
      if c = 0 then
      begin
        Search := True;
        if not Duplicates then
          L := I;
      end;
    end;
  end;
  Index := L;
end;

{ TStringColl }

function TStringColl.LongString: AnsiString;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to Count - 1 do
    Result := Result + Strings[I] + #13#10;
end;

function TStringColl.LongStringD(c: AnsiChar): AnsiString;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to Count - 2 do
    Result := Result + Strings[I] + c;
  for I := MaxI(0, Count - 1) to Count - 1 do
    Result := Result + Strings[I];
end;

procedure TStringColl.SetTextStr(const Value: AnsiString);
var
  P, Start: PAnsiChar;
  S: AnsiString;
begin
  if Value = '' then
    Exit;
  P := @(Value[1]);
  while P^ <> #0 do
  begin
    Start := P;
    while not(P^ in [#0, #10, #13]) do
      Inc(P);
    System.SetString(S, Start, P - Start);
    Add(S);
    if P^ = #13 then
      Inc(P);
    if P^ = #10 then
      Inc(P);
  end;
end;

procedure TStringColl.FillEnum(Str: AnsiString; Delim: AnsiChar;
  Sorted: Boolean);
var
  z: AnsiString;
begin
  while Str <> '' do
  begin
    z := '';
    GetWrd(Str, z, Delim);
    if Sorted then
      Ins(z)
    else
      Add(z);
  end;
end;

function TStringColl.Found(const Str: AnsiString): Boolean;
var
  I: Integer;
begin
  I := -1;
  Result := Search(@Str, I);
end;

function TStringColl.FoundU(const Str: AnsiString): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 0 to Count - 1 do
    if Str = Strings[I] then
    begin
      Result := True;
      Exit
    end;
end;

function TStringColl.FoundUC(const Str: AnsiString): Boolean;
var
  us: AnsiString;
  I: Integer;
begin
  us := UpperCase(Str);
  Result := False;
  for I := 0 to Count - 1 do
    if us = UpperCase(Strings[I]) then
    begin
      Result := True;
      Exit
    end;
end;

function TStringColl.Copy: Pointer;
begin
  Result := TStringColl.Create;
  CopyItemsTo(TColl(Result));
end;

function TStringColl.CopyItem(AItem: Pointer): Pointer;
begin
  Result := NewStr(PAnsiString(AItem)^);
end;

function TStringColl.KeyOf(Item: Pointer): Pointer;
begin
  KeyOf := Item;
end;

procedure TStringColl.Concat(AColl: TStringColl);
var
  I: Integer;
begin
  for I := 0 to AColl.Count - 1 do
    AtInsert(Count, AColl.At(I));
  AColl.DeleteAll;
end;

procedure TStringColl.AppendTo(AColl: TStringColl);
var
  I: Integer;
begin
  for I := 0 to Count - 1 do
    AColl.Add(Strings[I]);
end;

procedure TStringColl.Fill(const AStrs: array of AnsiString);
var
  I: Integer;
begin
  FreeAll;
  for I := Low(AStrs) to High(AStrs) do
    Add(AStrs[I]);
end;

procedure TStringColl.AddStrings(AStrings: TStringColl; ASort: Boolean);
var
  I: Integer;
begin
  for I := 0 to AStrings.Count - 1 do
    if ASort then
      Ins(AStrings[I])
    else
      Add(AStrings[I]);
end;

function TStringColl.IdxOf(Item: AnsiString): Integer;
begin
  Result := IndexOf(@Item);
end;

procedure TStringColl.SetString(Index: Integer; const Value: AnsiString);
begin
  FreeItem(At(Index));
  AtPut(Index, NewStr(Value));
end;

function TStringColl.GetString(Index: Integer): AnsiString;
begin
  Result := PAnsiString(At(Index))^;
end;

function TStringColl.Compare(Key1, Key2: Pointer): Integer;
begin
  Compare := CompareStr(PAnsiString(Key1)^, PAnsiString(Key2)^);
end;

procedure TStringColl.FreeItem(Item: Pointer);
begin
  DisposeStr(Item);
end;

procedure TStringColl.AtIns(Index: Integer; const Item: AnsiString);
begin
  AtInsert(Index, NewStr(Item));
end;

procedure TStringColl.Add(const S: AnsiString);
begin
  AtInsert(Count, NewStr(S));
end;

procedure TStringColl.Ins0(const S: AnsiString);
begin
  AtInsert(0, NewStr(S));
end;

procedure TStringColl.Ins(const S: AnsiString);
begin
  Insert(NewStr(S));
end;

procedure FreeObject(var O);
var
  OO: TObject absolute O;
  OP: Pointer absolute O;
begin
  if OP <> nil then
  begin
    OO.Free;
    OP := nil
  end;
end;

function DeleteEmptyDirInheritance(S: AnsiString;
  const StopOn: AnsiString): Integer;
begin
  Result := 0;
  while (S <> StopOn) and (S <> '') and RemoveDirectoryA(@(S[1])) do
  begin
    Inc(Result);
    S := ExtractFileDir(S);
  end;
end;

const
  CMonths = 'JanFebMarAprMayJunJulAugSepOctNovDec';
  Months: string[Length(CMonths)] = CMonths;

function MonthE(m: Integer): AnsiString;
begin
  Result := Copy(Months, 1 + (m - 1) * 3, 3);
end;

procedure GlobalFail;
begin
  // WriteLn('Global Failure!!!');
  Halt;
end;

function CreateTCollEL: TColl;
begin
  Result := TColl.Create;
  TColl(Result).Enter;
  TColl(Result).Leave;
end;

procedure XorStr(P: PByteArray; Len: Integer; const S: AnsiString);
var
  sl, I: Integer;
begin
  sl := Length(S);
  if sl = 0 then
    Exit;
  for I := 0 to Len - 1 do
  begin
    P^[I] := P^[I] xor Byte(S[(I mod sl) + 1]);
  end;
end;

function GetEnvVariable(const Name: AnsiString): AnsiString;
const
  BufSize = 128;
var
  Buf: array [0 .. BufSize] of AnsiChar;
  I: DWORD;
begin
  if Name = '' then
  begin
    Result := '';
    Exit;
  end;
  I := GetEnvironmentVariableA(@(Name[1]), Buf, BufSize);
  case I of
    1 .. BufSize:
      begin
        SetLength(Result, I);
        Move(Buf, Result[1], I);
      end;
    BufSize + 1 .. MaxInt:
      begin
        SetLength(Result, I + 1);
        GetEnvironmentVariableA(@(Name[1]), @Result[1], I);
        SetLength(Result, I);
      end;
  else
    begin
      Result := '';
    end;
  end;
end;

function LoadRS(Ident: Integer): AnsiString;
const
  strbufsize = $10000;
var
  strbuf: array [0 .. strbufsize] of AnsiChar;
  BufPtr: PAnsiChar;
begin
  BufPtr := @(strbuf[0]);
  SetString(Result, BufPtr, LoadStringA(hInstance, Ident, BufPtr, strbufsize));
end;

function StrBegins(const S1, S2: AnsiString): Boolean;
begin
  Result := Copy(S1, 1, Length(S2)) = S2;
end;

function DivideDash(const S: AnsiString): AnsiString;
begin
  Result := S;
  Insert('-', Result, (Length(S) div 2) + 1);
end;

procedure MoveColl(Src, Dst: TColl; Idx: Integer);
begin
  if Idx = -1 then
    Exit;
  Dst.Insert(Src[Idx]);
  Src.AtDelete(Idx);
end;

function TempFileName(const APath, APfx: AnsiString): AnsiString;
var
  S: AnsiString;
begin
  if (APath = '') or (APfx = '') then
  begin
    Result := '';
    Exit;
  end;
  S := '';
  SetLength(S, 1000);
  GetTempFileNameA(@(APath[1]), @(APfx[1]), 0, @(S[1]));
  Result := Copy(S, 1, NulSearch(S[1]));
end;

function CreateTempFile(const APath, APfx: AnsiString;
  var FName: AnsiString): DWORD;
begin
  FName := TempFileName(APath, APfx);
  Result := _CreateFile(FName, [cWrite, cExisting]);
end;

{ TThread }

function ThreadProc(AThread: {$IFDEF FPC}Pointer{$ELSE}TThread{$ENDIF}):
{$IFDEF FPC}ptrint{$ELSE}DWORD{$ENDIF};
var
  FreeThread: Boolean;
  Thread: TThread;
begin
  Thread := {$IFDEF FPC}TThread{$ENDIF}(AThread);
  Thread.Execute;
  FreeThread := Thread.FFreeOnTerminate;
  Result := Thread.FReturnValue;
  Thread.FFinished := True;
  if FreeThread then
    Thread.Free;
  EndThread(Result);
end;

constructor TThread.Create(CreateSuspended: Boolean);
var
  Flags: DWORD;
  TF: {$IFDEF FPC}tthreadfunc{$ELSE}Pointer{$ENDIF};
begin
  inherited Create;
  FSuspended := CreateSuspended;
  Flags := 0;
  if CreateSuspended then
    Flags := CREATE_SUSPENDED;
  TF := @ThreadProc;
  FHandle := BeginThread(nil, 0, TF, Pointer(Self), Flags, FThreadID);
end;

destructor TThread.Destroy;
begin
  if FHandle <> 0 then
    CloseHandle(FHandle);
  inherited Destroy;
end;

const
  Priorities: array [TThreadPriority] of Integer = (THREAD_PRIORITY_IDLE,
    THREAD_PRIORITY_LOWEST, THREAD_PRIORITY_BELOW_NORMAL,
    THREAD_PRIORITY_NORMAL, THREAD_PRIORITY_ABOVE_NORMAL,
    THREAD_PRIORITY_HIGHEST, THREAD_PRIORITY_TIME_CRITICAL);

function TThread.GetPriority: TThreadPriority;
var
  P: Integer;
  I: TThreadPriority;
begin
  P := GetThreadPriority(FHandle);
  Result := tpNormal;
  for I := Low(TThreadPriority) to High(TThreadPriority) do
    if Priorities[I] = P then
      Result := I;
end;

procedure TThread.SetPriority(Value: TThreadPriority);
begin
  SetThreadPriority(FHandle, Priorities[Value]);
end;

procedure TThread.SetSuspended(Value: Boolean);
begin
  if Value <> FSuspended then
    if Value then
      Suspend
    else
      Resume;
end;

procedure TThread.Suspend;
begin
  FSuspended := True;
  SuspendThread(FHandle);
end;

procedure TThread.Resume;
begin
  if ResumeThread(FHandle) = 1 then
    FSuspended := False;
end;

procedure TThread.Terminate;
begin
  FTerminated := True;
end;

function NumBits(I: Integer): Integer; assembler;
asm
  bsr eax, eax
  jz @z
  inc eax
@z:
end;

function ExtractFilePath(const FileName: AnsiString): AnsiString;
var
  I: Integer;
begin
  I := LastDelimiter('\:', FileName);
  Result := Copy(FileName, 1, I);
end;

function ExtractFileDir(const FileName: AnsiString): AnsiString;
var
  I: Integer;
begin
  I := LastDelimiter('\:', FileName);
  if (I > 1) and (FileName[I] = '\') and (not(FileName[I - 1] in ['\', ':']))
  then
    Dec(I);
  Result := Copy(FileName, 1, I);
end;

function ExtractFileDrive(const FileName: AnsiString): AnsiString;
var
  I, J: Integer;
begin
  if (Length(FileName) >= 2) and (FileName[2] = ':') then
    Result := Copy(FileName, 1, 2)
  else if (Length(FileName) >= 2) and (FileName[1] = '\') and (FileName[2] = '\')
  then
  begin
    J := 0;
    I := 3;
    While (I < Length(FileName)) and (J < 2) do
    begin
      if FileName[I] = '\' then
        Inc(J);
      if J < 2 then
        Inc(I);
    end;
    if FileName[I] = '\' then
      Dec(I);
    Result := Copy(FileName, 1, I);
  end
  else
    Result := '';
end;

function LastDelimiter(const Delimiters, S: AnsiString): Integer;
begin
  Result := Length(S);
  while Result > 0 do
  begin
    if (S[Result] <> #0) and (Pos(S[Result], Delimiters) = 0) then
      Dec(Result)
    else
      Break;
  end;
end;

function ExtractFileName(const FileName: AnsiString): AnsiString;
var
  I: Integer;
begin
  I := LastDelimiter('\:', FileName);
  Result := Copy(FileName, I + 1, MaxInt);
end;

function ExtractFileExt(const FileName: AnsiString): AnsiString;
var
  I: Integer;
begin
  I := LastDelimiter('.\:', FileName);
  if (I > 0) and (FileName[I] = '.') then
    Result := Copy(FileName, I, MaxInt)
  else
    Result := '';
end;

function ExpandFileName(const FileName: AnsiString): AnsiString;
var
  FName: PAnsiChar;
  Buffer: array [0 .. MAX_PATH - 1] of AnsiChar;
begin
  if FileName = '' then
  begin
    Result := '';
  end
  else
  begin
    FillChar(Buffer, SizeOf(Buffer), 0);
    FName := nil;
    SetString(Result, Buffer, GetFullPathNameA(@(FileName[1]), SizeOf(Buffer),
      Buffer, FName));
  end;
end;

function UpperCase(const S: AnsiString): AnsiString;
var
  Ch: AnsiChar;
  L: Integer;
  Source, Dest: PAnsiChar;
begin
  L := Length(S);
  if L < 1 then
  begin
    Result := '';
    Exit;
  end;
  SetLength(Result, L);
  Source := @(S[1]);
  Dest := @(Result[1]);
  while L <> 0 do
  begin
    Ch := Source^;
    if (Ch >= 'a') and (Ch <= 'z') then
      Dec(Ch, 32);
    Dest^ := Ch;
    Inc(Source);
    Inc(Dest);
    Dec(L);
  end;
end;

function LowerCase(const S: AnsiString): AnsiString;
var
  Ch: AnsiChar;
  L: Integer;
  Source, Dest: PAnsiChar;
begin
  L := Length(S);
  if L < 1 then
  begin
    Result := '';
    Exit;
  end;
  SetLength(Result, L);
  Source := @(S[1]);
  Dest := @(Result[1]);
  while L <> 0 do
  begin
    Ch := Source^;
    if (Ch >= 'A') and (Ch <= 'Z') then
      Inc(Ch, 32);
    Dest^ := Ch;
    Inc(Source);
    Inc(Dest);
    Dec(L);
  end;
end;

const
  EmptyStr: AnsiString = '';
  NullStr: PAnsiString = @EmptyStr;

function NewStr(const S: AnsiString): PAnsiString;
begin
  if S = '' then
    Result := NullStr
  else
  begin
    New(Result);
    Result^ := S;
  end;
end;

procedure DisposeStr(P: PAnsiString);
begin
  if (P <> nil) and (P^ <> '') then
    Dispose(P);
end;

function CompareStr(const S1, S2: AnsiString): Integer; assembler;
asm
  PUSH    ESI
  PUSH    EDI
  MOV     ESI,EAX
  MOV     EDI,EDX
  OR      EAX,EAX
  JE      @@1
  MOV     EAX,[EAX-4]
@@1:    OR      EDX,EDX
  JE      @@2
  MOV     EDX,[EDX-4]
@@2:    MOV     ECX,EAX
  CMP     ECX,EDX
  JBE     @@3
  MOV     ECX,EDX
@@3:    CMP     ECX,ECX
  REPE    CMPSB
  JE      @@4
  MOVZX   EAX,BYTE PTR [ESI-1]
  MOVZX   EDX,BYTE PTR [EDI-1]
@@4:    SUB     EAX,EDX
  POP     EDI
  POP     ESI
end;

function CompareMem(P1, P2: Pointer; Length: Integer): Boolean; assembler;
asm
  PUSH    ESI
  PUSH    EDI
  MOV     ESI,P1
  MOV     EDI,P2
  MOV     EDX,ECX
  XOR     EAX,EAX
  AND     EDX,3
  SHR     ECX,1
  SHR     ECX,1
  REPE    CMPSD
  JNE     @@2
  MOV     ECX,EDX
  REPE    CMPSB
  JNE     @@2
@@1:    INC     EAX
@@2:    POP     EDI
  POP     ESI
end;

procedure TSocket.RegisterSelf;
begin
  SocketsColl.Enter;
  SocketsColl.Insert(Self);
  Registered := True;
  SocketsColl.Leave;
end;

procedure TSocket.DeregisterSelf;
begin
  SocketsColl.Enter;
  if Registered then
    SocketsColl.Delete(Self);
  Registered := False;
  SocketsColl.Leave;
end;

function TSocket.Startup: Boolean;
begin
  Result := True;
end;

function TSocket.Handshake: Boolean;
begin
  Result := True;
end;

destructor TSocket.Destroy;
begin
  DeregisterSelf;
  CloseSocket(Handle);
  SocketsColl.Enter;
  Dec(SocksCount);
  if SocksCount = 0 then
    ResetterThread.TimeToSleep := INFINITE;
  SocketsColl.Leave;
  inherited Destroy;
end;

function TSocket.Read(var B; Size: DWORD): DWORD;
begin
  Result := _Read(B, Size);
  Dead := 0;
end;

function TSocket.Write(const B; Size: DWORD): DWORD;
const
  cWrite = $4000;
var
  P: PByteArray;
  Written, Left, I, WriteNow: DWORD;
begin
  P := @B;
  I := 0;
  Left := Size;
  while Left > 0 do
  begin
    WriteNow := MinD(Left, cWrite);
    Written := _Write(P^[I], WriteNow);
    Dead := 0;
    Inc(I, Written);
    Dec(Left, Written);
    if Written <> WriteNow then
      Break;
  end;
  Result := I;
end;

function TSocket.WriteStr(const S: AnsiString): DWORD;
var
  slen: Integer;
begin
  slen := Length(S);
  if slen > 0 then
    Result := Write(S[1], slen)
  else
    Result := 0;
end;

function TSocket._Write(const B; Size: DWORD): DWORD;
var
  I: Integer;
begin
  I := send(Handle, (@B)^, Size, 0);
  if (I = SOCKET_ERROR) or (I < 0) then
  begin
    Status := WSAGetLastError;
    Result := 0
  end
  else
    Result := I;
end;

function TSocket._Read(var B; Size: DWORD): DWORD;
var
  I: Integer;
begin
  I := recv(Handle, B, Size, 0);
  if (I = SOCKET_ERROR) or (I < 0) then
  begin
    Status := WSAGetLastError;
    Result := 0
  end
  else
    Result := I;
end;

function Inet2addr(const S: AnsiString): DWORD;
begin
  if S = '' then
  begin
    Result := 0;
  end
  else
  begin
    Result := inet_addr(@(S[1]));
  end;
end;

function __pchar(c: AnsiChar): Boolean;
begin
  case c of
    ':', '@', '&', '=', '+':
      Result := True
  else
    Result := __uchar(c)
  end;
end;

function __uchar(c: AnsiChar): Boolean;
begin
  Result := __alpha(c) or __digit(c) or __safe(c) or __extra(c) or __national(c)
end;

function __national(c: AnsiChar): Boolean;
begin
  case c of
    '0' .. '9', 'A' .. 'Z', 'a' .. 'z':
      Result := False;
  else
    Result := not(__reserved(c) or __extra(c) or __safe(c) or __unsafe(c));
  end;
end;

function __reserved(c: AnsiChar): Boolean;
begin
  case c of
    ';', '/', '?', ':', '@', '&', '=', '+':
      Result := True
  else
    Result := False;
  end;
end;

function __extra(c: AnsiChar): Boolean;
begin
  case c of
    '!', '*', '''', '(', ')', ',':
      Result := True
  else
    Result := False;
  end;
end;

function __safe(c: AnsiChar): Boolean;
begin
  case c of
    '$', '-', '_', '.':
      Result := True
  else
    Result := False;
  end;
end;

function __unsafe(c: AnsiChar): Boolean;
begin
  case c of
    '"', '#', '%', '<', '>':
      Result := True;
  else
    Result := __ctl(c);
  end;
end;

function __alpha(c: AnsiChar): Boolean;
begin
  case c of
    'A' .. 'Z', 'a' .. 'z':
      Result := True
  else
    Result := False;
  end;
end;

function __digit(c: AnsiChar): Boolean;
begin
  case c of
    '0' .. '9':
      Result := True
  else
    Result := False;
  end;
end;

function __ctl(c: AnsiChar): Boolean;
begin
  case c of
    #0 .. #31, #127:
      Result := True
  else
    Result := False;
  end;
end;

function UnpackXchars(var S: AnsiString; P: Boolean): Boolean;
var
  R: AnsiString;
  c: AnsiChar;
  I, H, L, sl: Integer;

begin
  Result := False;
  R := '';
  sl := Length(S);
  I := 0;
  while I < sl do
  begin
    Inc(I);
    c := S[I];
    if c = '%' then
    begin
      if I > sl - 2 then
        Exit;
      L := Pos(UpCase(S[I + 2]), rrHiHexChar) - 1;
      H := Pos(UpCase(S[I + 1]), rrHiHexChar) - 1;
      if (H = -1) or (L = -1) then
        Exit;
      R := R + AnsiChar(H shl 4 or L);
      Inc(I, 2);
      Continue;
    end;
    if P then
    begin
      if not __pchar(c) and (c <> '/') then
        Exit;
    end
    else
    begin
      if not __uchar(c) then
        Exit
    end;
    R := R + c;
  end;
  S := R;
  Result := True;
end;

function UnpackUchars(var S: AnsiString): Boolean;
begin
  Result := UnpackXchars(S, False);
end;

function UnpackPchars(var S: AnsiString): Boolean;
begin
  Result := UnpackXchars(S, True);
end;

function ProcessQuotes(var S: AnsiString): Boolean;
var
  R: AnsiString;
  I: Integer;
  KVC: Boolean;
  c: AnsiChar;
begin
  Result := False;
  R := '';
  KVC := False;
  for I := 1 to Length(S) do
  begin
    c := S[I];
    case c of
      #0 .. #9, #11 .. #12, #14 .. #31:
        Exit;
      '"':
        begin
          KVC := not KVC;
          Continue
        end;
    end;
    if KVC then
      R := R + '%' + Hex2(Byte(c))
    else
      R := R + c;
  end;
  Result := not KVC;
  if Result then
    S := R;
end;

function _Val(const S: AnsiString; var V: Integer): Boolean;
var
  I, R: Integer;
  c: AnsiChar;
begin
  Result := False;
  if S = '' then
    Exit;
  R := 0;
  for I := 1 to Length(S) do
  begin
    c := S[I];
    if not __digit(c) then
      Exit;
    R := (R * 10) + Ord(c) - Ord('0');
  end;
  Result := True;
  V := R;
end;

function StoI(const S: AnsiString): Integer;
begin
  Result := 0;
  if not _Val(S, Result) then
    Result := 0;
end;

function _LogOK(const Name: AnsiString; var Handle: THandle): Boolean;
begin
  if Handle = 0 then
  begin
    Handle := _CreateFile(Name, [cWrite]);
    if Handle <> INVALID_HANDLE_VALUE then
      if SetFilePointer(Handle, 0, nil, FILE_END) = INVALID_FILE_SIZE then
        ClearHandle(Handle);
  end;
  Result := Handle <> INVALID_HANDLE_VALUE;
end;

function AddrInet(I: DWORD): AnsiString;
var
  R: record a, B, c, D: Byte end absolute I;
begin
  Result := ItoS(R.a) + '.' + ItoS(R.B) + '.' + ItoS(R.c) + '.' + ItoS(R.D);
end;

const
  shell32 = 'shell32.dll';

function FindExecutable(FileName, Directory: PAnsiChar; Result: PAnsiChar)
  : HINST; stdcall; external shell32 name 'FindExecutableA';

procedure XAdd(var Critical, Normal); assembler;
asm
  mov  ecx, [edx]
  xadd [eax], ecx  // !!! i486+
  mov  [edx], ecx
end;

procedure GetBias;
var
  T, L: TFileTime;
  a, B, c: DWORD;
begin
  FillChar(T, SizeOf(T), 0);
  FillChar(L, SizeOf(L), 0);
  GetSystemTimeAsFileTime(T);
  if not FileTimeToLocalFileTime(T, L) then Exit;
  a := uCvtGetFileTime(T.dwLowDateTime, T.dwHighDateTime);
  B := uCvtGetFileTime(L.dwLowDateTime, L.dwHighDateTime);
  if a > B then
  begin
    c := a - B;
    TimeZoneBias := c;
  end
  else
  begin
    c := B - a;
    TimeZoneBias := c;
    TimeZoneBias := -TimeZoneBias;
  end;
end;

type
  THostCache = class
    Addr: DWORD;
    Name: AnsiString;
  end;

  THostCacheColl = class(TSortedColl)
    function Compare(Key1, Key2: Pointer): Integer; override;
    function KeyOf(Item: Pointer): Pointer; override;
  end;

var
  HostCache: THostCacheColl;

function THostCacheColl.Compare(Key1, Key2: Pointer): Integer;
begin
  Result := NativeInt(Key1) - NativeInt(Key2);
end;

function THostCacheColl.KeyOf(Item: Pointer): Pointer;
begin
  Result := Pointer(THostCache(Item).Addr);
end;

function GetHostNameByAddr(Addr: DWORD): AnsiString;
var
  P: PHostEnt;
  I: Integer;
  F: Boolean;
  c: THostCache;
  ok: Boolean;
  he: PHostEnt;
  HostName: AnsiString;
begin
  HostCache.Enter;
  I := -1;
  F := HostCache.Search(Pointer(Addr), I);
  if F then
    Result := StrAsg(THostCache(HostCache[I]).Name);
  HostCache.Leave;
  if F then
    Exit;
  P := gethostbyaddr(@Addr, 4, PF_INET);
  ok := False;
  if P <> nil then
  begin // host name got - now get address of this name
    HostName := P^.h_name;
    if HostName = '' then
    begin
      he := nil;
    end
    else
    begin
      he := gethostbyname(@(HostName[1]));
    end;
    if (he <> nil) and (he^.h_addr_list <> nil) then
    begin // address got - now compare it with the real one
      ok := PDwordArray(he^.h_addr_list^)^[0] = Addr;
    end;
  end;
  if ok then
    Result := HostName
  else
    Result := AddrInet(Addr);
  HostCache.Enter;
  F := HostCache.Search(Pointer(Addr), I);
  if not F then
  begin
    c := THostCache.Create;
    c.Addr := Addr;
    c.Name := StrAsg(Result);
    HostCache.AtInsert(I, c);
  end;
  HostCache.Leave;
end;

function Vl(const S: AnsiString): DWORD;
var
  a, I, L: Integer;
  c: AnsiChar;
begin
  Result := INVALID_VALUE;
  L := Length(S);
  if L > 9 then
    Exit;
  a := 0;
  for I := 1 to L do
  begin
    c := S[I];
    if (c < '0') or (c > '9') then
      Exit;
    a := a * 10 + Ord(c) - Ord('0');
  end;
  Result := a;
end;

function VlH(const S: AnsiString): DWORD;
var
  a, I, L, Start: DWORD;
  c: AnsiChar;
begin
  Result := INVALID_VALUE;
  L := Length(S);
  Start := 0;
  if (L = 0) then
    Exit;
  while (Start < L - 1) and (S[Start + 1] = '0') do
    Inc(Start);
  if (L - Start > 8) then
    Exit;
  a := 0;
  for I := 1 + Start to L do
  begin
    c := S[I];
    a := a shl 4;
    case c of
      '0' .. '9':
        Inc(a, Ord(c) - Ord('0'));
      'A' .. 'F':
        Inc(a, Ord(c) - Ord('A') + 10);
      'a' .. 'f':
        Inc(a, Ord(c) - Ord('a') + 10);
    else
      Exit;
    end;
  end;
  Result := a;
end;

procedure xBaseInit;
begin
  GetBias;
  HostCache := THostCacheColl.Create;
  HostCache.Enter;
  HostCache.Leave;
end;

procedure xBaseDone;
begin
  FreeObject(HostCache);
end;

constructor TResetterThread.Create;
begin
  inherited Create(False);
  oSleep := CreateEvent(nil, False, False, nil);
  TimeToSleep := INFINITE;
end;

destructor TResetterThread.Destroy;
begin
  CloseHandle(oSleep);
  inherited Destroy;
end;

procedure TResetterThread.Execute;
const
  KillQuants = 5; // Quants to shut down socket for inactivity
var
  I: Integer;
  S: TSocket;
  P: Pointer;
begin
  repeat
    WaitForSingleObject(oSleep, TimeToSleep);
    if Terminated then
      Break;
    SocketsColl.Enter;
    for I := 0 to SocketsColl.Count - 1 do
    begin
      P := SocketsColl[I];
      S := TSocket(P);
      if S.Dead < 0 then
        Continue; // Already shut down
      Inc(S.Dead);
      if S.Dead <= KillQuants then
        Continue; // This one shows activity - let him live
      S.Dead := -1; // Mark
      // disable both sends and receives
      shutdown(S.Handle, 2);
    end;
    SocketsColl.Leave;
  until Terminated;
end;

function CompareMask(const N, m: AnsiString; SupportPercent: Boolean): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to Length(m) do
  begin
    if (m[I] = '?') then
      Continue;
    if (I > Length(N)) or (N[I] <> m[I]) then
    begin
      if SupportPercent and (m[I] = '%') and (N[I] in ['0' .. '9']) then
      else
        Exit;
    end;
  end;
  Result := True;
end;

function PosMask(const m, S: AnsiString; SupportPercent: Boolean): Integer;
var
  I: Integer;
begin
  Result := 0;
  for I := 1 to Length(S) - Length(m) + 1 do
  begin
    if CompareMask(Copy(S, I, Length(m)), m, SupportPercent) then
    begin
      Result := I;
      Exit;
    end;
  end;
end;

function MatchMask(const AName, AMask: AnsiString): Boolean;
begin
  Result := _MatchMask(AName, AMask, False);
end;

function _MatchMaskBody(AName, AMask: AnsiString;
  SupportPercent: Boolean): Boolean;
var
  I, J: Integer;
  Scan: Boolean;
  CASterisk: AnsiChar;
begin
  Result := False;
  Scan := False;
  CASterisk := '*';
  while True do
  begin
    I := Pos(CASterisk, AMask);
    if I = 0 then
    begin
      if AMask = '' then
      begin
        Result := True;
        Exit
      end;
      J := PosMask(AMask, AName, SupportPercent);
      if J = 0 then
        Exit;
      if (J + Length(AMask)) <= Length(AName) then
        Exit;
      Result := True;
      Exit;
    end
    else
    begin
      if I > 1 then
      begin
        if Scan then
          J := PosMask(Copy(AMask, 1, I - 1), AName, SupportPercent)
        else if CompareMask(AName, Copy(AMask, 1, I - 1), SupportPercent) then
          J := I - 1
        else
          J := 0;
        if J = 0 then
          Exit
        else
          Delete(AName, 1, J);
      end;
      Delete(AMask, 1, I);
    end;
    Scan := True;
  end;
end;

function _MatchMask(const AName: AnsiString; AMask: AnsiString;
  SupportPercent: Boolean): Boolean;
begin
  Replace('?*', '*', AMask);
  Replace('*?', '*', AMask);
  Replace('**', '*', AMask);
  Result := _MatchMaskBody(UpperCase(AName), UpperCase(AMask), SupportPercent);
end;

function FromHex(C1, C2: AnsiChar): AnsiChar;
var
  I1, I2: Byte;
begin
  case C1 of
    '0' .. '9':
      I1 := Byte(C1) - 48;
    'A' .. 'F':
      I1 := Byte(C1) - 55;
    'a' .. 'f':
      I1 := Byte(C1) - 87;
  else
    I1 := 0;
  end;
  case C2 of
    '0' .. '9':
      I2 := Byte(C2) - 48;
    'A' .. 'F':
      I2 := Byte(C2) - 55;
    'a' .. 'f':
      I2 := Byte(C2) - 87;
  else
    I2 := 0;
  end;
  Result := AnsiChar(I1 shl 4 + I2);
end;

constructor TMimeCoder.Create(AType: TBase64Table);
begin
  case AType of
    bsBase64:
      begin
        Table := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        MaxChars := 57;
        Pad := '=';
      end;
    bsUUE:
      begin
        Table := '`!"#$%&''()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_';
        Pad := '`';
        MaxChars := 45;
      end;
    bsXXE:
      begin
        Table := '+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        Pad := '+';
        MaxChars := 45;
      end;
  end;
  InitTable;
end;

procedure TMimeCoder.InitTable;
var
  I: Integer;
begin
  FillChar(XChars, SizeOf(XChars), 65);
  for I := 1 to Length(Table) do
    XChars[Table[I]] := I - 1;
  XChars[Pad] := 0;
  if Pad = '`' then
    XChars[' '] := 0;
end;

function TMimeCoder.EncodeStr(const S: AnsiString): AnsiString;
begin
  if S = '' then
    Result := ''
  else
    Result := Encode(S[1], Length(S));
end;

function IsUUEStr(const S: AnsiString): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to Length(S) do
    if (S[I] < '!') or (S[I] > '`') then
      Exit;
  Result := True;
end;

function TMimeCoder.Encode(const Buf; N: Byte): AnsiString;
var
  B: Array [0 .. MMaxChars] of Byte;
  I, K, L: Word;
  S: Str255;
begin
  FillChar(B, SizeOf(B), 0);
  Move(Buf, B, N);
  L := N;
  if L mod 3 <> 0 then
    Inc(L, 3);
  S[0] := AnsiChar((L div 3) * 4);
  FillChar(S[1], Length(S), Pad);
  I := 0;
  K := 1;
  while I < N do
  begin
    S[K] := Table[1 + (B[I] shr 2)];
    S[K + 1] := Table[1 + (((B[I] and $03) shl 4) or (B[I + 1] shr 4))];
    if I + 1 >= N then
      Break;
    S[K + 2] := Table[1 + (((B[I + 1] and $0F) shl 2) or (B[I + 2] shr 6))];
    if I + 2 >= N then
      Break;
    S[K + 3] := Table[1 + (B[I + 2] and $3F)];
    Inc(I, 3);
    Inc(K, 4);
  end;
  Result := S;
end;

function TMimeCoder.EncodeBuf(const Buf; N: Byte; var OutBuf): Integer;
var
  B: Array [0 .. MMaxChars] of Byte;
  I, K, L: Word;
  P: PCharArray;
begin
  P := @OutBuf;
  FillChar(B, SizeOf(B), 0);
  Move(Buf, B, N);
  L := N;
  if L mod 3 <> 0 then
    Inc(L, 3);
  Result := (L div 3) * 4;
  FillChar(P^, Result, Pad);
  I := 0;
  K := 0;
  while I < N do
  begin
    P^[K] := Table[1 + (B[I] shr 2)];
    P^[K + 1] := Table[1 + (((B[I] and $03) shl 4) or (B[I + 1] shr 4))];
    if I + 1 >= N then
      Break;
    P^[K + 2] := Table[1 + (((B[I + 1] and $0F) shl 2) or (B[I + 2] shr 6))];
    if I + 2 >= N then
      Break;
    P^[K + 3] := Table[1 + (B[I + 2] and $3F)];
    Inc(I, 3);
    Inc(K, 4);
  end;
end;

function TMimeCoder.Decode(const S: AnsiString; var Buf): Integer;
var
  B: array [0 .. MMaxChars] of Byte absolute Buf;
  a: array [0 .. MMaxChars] of Byte;
  I, J, K, Pdd: Integer;
begin
  if S = '' then
  begin
    Result := 0;
    Exit
  end;
  Result := -1;
  FillChar(a, SizeOf(a), 0);
  for I := 0 to Length(S) - 1 do
  begin
    a[I] := XChars[S[I + 1]];
    if a[I] > 64 then
      Exit;
  end;
  J := Length(S);
  Pdd := 3;
  if (Pad = '=') then
    while S[J] = Pad do
    begin
      Dec(Pdd);
      Dec(J)
    end;
  Pdd := Pdd mod 3;
  Result := (J div 4) * 3 + Pdd;
  I := 0;
  K := 0;
  while I < J do
  begin
    B[K] := ((a[I] shl 2) or (a[I + 1] shr 4)) and $FF;
    B[K + 1] := ((a[I + 1] shl 4) or (a[I + 2] shr 2)) and $FF;
    B[K + 2] := ((a[I + 2] shl 6) or (a[I + 3])) and $FF;
    Inc(I, 4);
    Inc(K, 3);
  end;
end;

function TMimeCoder.DecodeBuf(const SrcBuf; SrcLen: Integer; var Buf): Integer;
var
  B: array [0 .. MMaxChars] of Byte absolute Buf;
  a: array [0 .. MMaxChars] of Byte;
  I, J, K, Pdd: Integer;
  P: PByteArray;
begin
  P := @SrcBuf;
  if SrcLen = 0 then
  begin
    Result := 0;
    Exit
  end;
  Result := -1;
  FillChar(a, SizeOf(a), 0);
  for I := 0 to SrcLen - 1 do
  begin
    a[I] := XChars[AnsiChar(P^[I])];
    if a[I] > 64 then
      Exit;
  end;
  J := SrcLen;
  Pdd := 3;
  if (Pad = '=') then
    while (J > 0) and (AnsiChar(P^[J - 1]) = Pad) do
    begin
      Dec(Pdd);
      Dec(J)
    end;
  Pdd := Pdd mod 3;
  Result := (J div 4) * 3 + Pdd;
  I := 0;
  K := 0;
  while I < J do
  begin
    B[K] := ((a[I] shl 2) or (a[I + 1] shr 4)) and $FF;
    B[K + 1] := ((a[I + 1] shl 4) or (a[I + 2] shr 2)) and $FF;
    B[K + 2] := ((a[I + 2] shl 6) or (a[I + 3])) and $FF;
    Inc(I, 4);
    Inc(K, 3);
  end;
end;

function StrAsg(const Src: AnsiString): AnsiString;
begin
  if Src = '' then
    Result := ''
  else
  begin
    SetLength(Result, Length(Src));
    Move(Src[1], Result[1], Length(Src));
  end;
end;

function UnicodeStringToRawByteString(const w: UnicodeString; CP: Integer)
  : RawByteString;
var
  P: PWideChar;
  I, J: Integer;
begin
  Result := '';
  if w = '' then
    Exit;
  P := @w[1];
  I := WideCharToMultibyte(CP, 0, P, Length(w), nil, 0, nil, nil);
  if I <= 0 then
    Exit;
  SetLength(Result, I);
  J := WideCharToMultibyte(CP, 0, P, Length(w), @Result[1], I, nil, nil);
  if I <> J then
  begin
    SetLength(Result, MinI(I, J));
  end;
{$IFDEF UNICODE}
  SetCodePage(Result, CP, False);
{$ENDIF}
end;

end.
