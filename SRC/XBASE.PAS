//////////////////////////////////////////////////////////////////////////
//
//  TinyWeb Copyright (C) 1997 RIT Research Labs
//
//  This programs is free for commercial and non-commercial use as long as
//  the following conditions are aheared to.
//
//  Copyright remains RIT Research Labs, and as such any Copyright notices
//  in the code are not to be removed. If this package is used in a
//  product, RIT Research Labs should be given attribution as the RIT Research
//  Labs of the parts of the library used. This can be in the form of a textual
//  message at program startup or in documentation (online or textual)
//  provided with the package.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//  1. Redistributions of source code must retain the copyright
//     notice, this list of conditions and the following disclaimer.
//  2. Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in the
//     documentation and/or other materials provided with the distribution.
//  3. All advertising materials mentioning features or use of this software
//     must display the following acknowledgement:
//     "Based on TinyWeb Server by RIT Research Labs."
//
//  THIS SOFTWARE IS PROVIDED BY RIT RESEARCH LABS "AS IS" AND ANY EXPRESS
//  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
//  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
//  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
//  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
//  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
//  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//  The licence and distribution terms for any publically available
//  version or derivative of this code cannot be changed. i.e. this code
//  cannot simply be copied and put under another distribution licence
//  (including the GNU Public Licence).
//
//////////////////////////////////////////////////////////////////////////

{$I DEFINE.INC}


unit xBase;

interface uses Windows, WinSock;

const

  _INADDR_ANY = INADDR_ANY;

  rrLoHexChar: array[0..$F] of char='0123456789abcdef';
  rrHiHexChar: array[0..$F] of char='0123456789ABCDEF';

{ Maximum TColl size }

  MaxCollSize = $20000 div SizeOf(Pointer);

type

    TSocketOption = (soBroadcast, soDebug, soDontLinger,
                     soDontRoute, soKeepAlive, soOOBInLine,
                     soReuseAddr, soNoDelay, soBlocking, soAcceptConn);

    TSocketOptions = Set of TSocketOption;

    TSocketClass = class of TSocket;

    TSocket = class
    public
      Dead: Integer;
      FPort: Integer;
      FAddr: Integer;
      Handle: Integer;
      Status: Integer;
      Registered: Boolean;
      procedure RegisterSelf;
      procedure DeregisterSelf;

      function Startup: Boolean; virtual;
      function Handshake: Boolean; virtual;
      destructor Destroy; override;

      function Read(var B; Size: Integer): Integer;
      function Write(const B; Size: Integer): Integer;
      function WriteStr(const s: string): Integer;

      function _Write(const B; Size: Integer): Integer; virtual;
      function _Read(var B; Size: Integer): Integer; virtual;

    end;

  TObjProc = procedure of object;
  TForEachProc = procedure(P: Pointer) of object;

  PFileInfo = ^TFileInfo;
  TFileInfo = record
    Attr: Integer;
    Size: Integer;
    Time: Integer;
  end;

  TuFindData = record
    Info: TFileInfo;
    FName: string;
  end;

  TCreateFileMode = (

   cRead,            // Specifies read access to the file
   cWrite,           // Specifies write access to the file

   cFlag,

   cEnsureNew,       // Creates a NEW file. The function fails
                     // if the specified file already exists.

   cTruncate,        // Once opened, the file is truncated so that
                     // its size is zero bytes.

   cExisting,        //  For communications resources, console diveces

   cShareAllowWrite,
   cShareDenyRead,

   cOverlapped,      // This flag enables more than one operation to be
                     // performed simultaneously with the handle
                     // (e.g. a simultaneous read and write operation).

   cRandomAccess,    // Indicates that the file is accessed randomly.
                     // Windows uses this flag to optimize file caching.

   cSequentialScan,  // Indicates that the file is to be accessed
                     // sequentially from beginning to end.

   cDeleteOnClose    // Indicates that the operating system is to delete
                     // the file immediately after all of its handles
                     // have been closed.

                    );

   TCreateFileModeSet = set of TCreateFileMode;

{ Character set type }

  PCharSet = ^TCharSet;
  TCharSet = set of Char;

{ General arrays }


  PCharArray = ^TCharArray;
  TCharArray = array[0..MaxLongInt-1] of Char;

  PByteArray = ^TByteArray;
  TByteArray = array[0..MaxLongInt-1] of Byte;

  PIntArray = ^TIntArray;
  TIntArray = array[0..(MaxLongInt div 4)-1] of Integer;

  PvIntArr = ^TvIntArr;
  TvIntArr = record
    Arr: PIntArray;
    Cnt: Integer;
  end;

  PBoolean   = ^Boolean;


  PItemList = ^TItemList;
  TItemList = array[0..MaxCollSize - 1] of Pointer;

  TThreadMethod = procedure of object;
  TThreadPriority = (tpIdle, tpLowest, tpLower, tpNormal, tpHigher, tpHighest,
    tpTimeCritical);

  TThread = class
  private
    FHandle: THandle;
    FThreadID: THandle;
    FTerminated: Boolean;
    FSuspended: Boolean;
    FFreeOnTerminate: Boolean;
    FFinished: Boolean;
    FReturnValue: Integer;
    function GetPriority: TThreadPriority;
    procedure SetPriority(Value: TThreadPriority);
    procedure SetSuspended(Value: Boolean);
  protected
    procedure Execute; virtual; abstract;
    property ReturnValue: Integer read FReturnValue write FReturnValue;
    property Terminated: Boolean read FTerminated;
  public
    constructor Create(CreateSuspended: Boolean);
    destructor Destroy; override;
    procedure Resume;
    procedure Suspend;
    procedure Terminate;
    property FreeOnTerminate: Boolean read FFreeOnTerminate write FFreeOnTerminate;
    property Handle: THandle read FHandle;
    property Priority: TThreadPriority read GetPriority write SetPriority;
    property Suspended: Boolean read FSuspended write SetSuspended;
    property ThreadID: THandle read FThreadID;
  end;

  TAdvObject = class;

  TAdvObject = class
  end;

  TAdvCpObject = class(TAdvObject)
    function Copy: Pointer; virtual; abstract;
  end;

  TAdvClass = class of TAdvObject;

  TCollClass = class of TColl;

  TListSortCompare = function (Item1, Item2: Pointer): Integer;

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
    function CopyItem(AItem: Pointer): Pointer; override;
    function Compare(Key1, Key2: Pointer): Integer; override;
    procedure FreeItem(Item: Pointer); override;
    procedure SetString(Index: Integer; const Value: string);
    function GetString(Index: Integer): string;
    function KeyOf(Item: Pointer): Pointer; override;
  public
    function Copy: Pointer; override;
    procedure Ins(const S: string);
    procedure Ins0(const S: string);
    procedure Add(const S: string);
    procedure AtIns(Index: Integer; const Item: string);
    property Strings[Index: Integer]: string read GetString write SetString; default;
    function  IdxOf(Item: string): Integer;
    procedure AppendTo(AColl: TStringColl);
    procedure Concat(AColl: TStringColl);
    procedure AddStrings(Strings: TStringColl; Sort: Boolean);
    procedure Fill(const AStrs: array of string);
    function Found(const Str: string): Boolean;
    function FoundU(const Str: string): Boolean;
    function FoundUC(const Str: string): Boolean;
    procedure FillEnum(Str: string; Delim: Char; Sorted: Boolean);
    function LongString: string;
    function LongStringD(c: char): string;
  end;


{ --- string routines }

function  AddRightSpaces(const S: string; NumSpaces: Integer): string;
procedure AddStr(var S: string ; C : char);
procedure Add_Str(var S: ShortString ; C : char);
function  CompareStr(const S1, S2: string): Integer; assembler;
function  CopyLeft(const S: string; I: Integer): string;
procedure DelDoubles(const St : string;var Source : string);
procedure DelFC(var s: string);
procedure DelLC(var s: string);
function  DelLeft(const S: string): string;
function  DelRight(const S: string): string;
function  DelSpaces(const s: string): string;
procedure DeleteLeft(var S: string; I: Integer);
function  DigitsOnly(const AStr: string): Boolean;
procedure DisposeStr(P: PString);
function  ExpandFileName(const FileName: string): string;
function  ExtractFilePath(const FileName: string): string;
function  ExtractDir(const S: string): string;
function  ExtractFileRoot(const FileName: string): string;
function  ExtractFileExt(const FileName: string): string;
function  ExtractFileName(const FileName: string): string;
function  ExtractFileDrive(const FileName: string): string;
function  ExtractFileDir(const FileName: string): string;
procedure FSplit(const FName: string; var Path, Name, Ext: string);
procedure FillCharSet(const AStr: string; var CharSet: TCharSet);
procedure GetWrdStrictUC(var s,w:string);
procedure GetWrdStrict(var s,w:string);
procedure GetWrd(var s,w:string;c:char);
function  Hex2(a: Byte): string;
function  Hex4(a: Word): string;
function  Hex8(a: Integer): string;
function  Int2Hex(a: Integer): string;
function  Int2Str(L: Integer): string;
function  ItoS(I: Integer): string;
function  ItoSz(I, Width: Integer): string;
function  LastDelimiter(const Delimiters, S: string): Integer;
function  LowerCase(const S: string): string;
function  MakeFullDir(const D, S: string): string;
function  MakeNormName(const Path, Name: string): string;
function  MonthE(m: Integer): string;
function  NewStr(const S: string): PString;
function  Replace(const Pattern, ReplaceString: string; var S: string): Boolean;
function  StoI(const S: string): Integer;
function  StrEnds(const S1, S2: string): Boolean;
function  StrRight(const S: string; Num: Integer): string;
function  UpperCase(const S: string): string;
function  WipeChars(const AStr, AWipeChars: string): string;
function  _Val(const S: string; var V: Integer): Boolean;

{ --- RFC Routines }

function  ProcessQuotes(var s: string): Boolean;
function  UnpackPchars(var s: string): Boolean;
function  UnpackUchars(var s: string): Boolean;
function  __alpha(c: char): Boolean;
function  __ctl(c: char): Boolean;
function  __digit(c: char): Boolean;
function  __extra(c: char): Boolean;
function  __national(c: char): Boolean;
function  __pchar(c: char): Boolean;
function  __reserved(c: char): Boolean;
function  __safe(c: char): Boolean;
function  __uchar(c: char): Boolean;
function  __unsafe(c: char): Boolean;

{ --- Basic Routines }

function  Buf2Str(const Buffer): string;
procedure Clear(var Buf; Count: Integer);
function  CompareMem(P1, P2: Pointer; Length: Integer): Boolean; assembler;
procedure FreeObject(var O);
procedure LowerPrec(var A, B: Integer; Bits: Byte);
function  Max(A, B: Integer): Integer;
function  MemEqu(const A, B; Sz: Integer): Boolean;
function  Min(A, B: Integer): Integer;
function  NulSearch(const Buffer): Integer;
function  NumBits(I: Integer): Integer;
procedure XAdd(var Critical, Normal: Integer); assembler;
procedure XChg(var Critical, Normal: Integer); assembler;

{ --- Win32 Events Extentions }

function  CreateEvtA: Integer;
function  CreateEvt(Initial: Boolean): Integer;
function  SignaledEvt(id: Integer): Boolean;
function  WaitEvt(const id: TWOHandleArray; Timeout: Integer): Integer;
function  WaitEvtA(nCount: Integer; lpHandles: PWOHandleArray; Timeout: Integer): Integer;

{ --- Win32 API Hooks }

function  ClearHandle(var Handle: Integer): Boolean;
procedure CloseHandles(const Handles: array of Integer);
function  FileExists(const FName: string): Boolean;
function  FindExecutable(FileName, Directory: PChar; Result: PChar): HINST; stdcall;
function  GetEnvVariable(const Name: string): string;
function  GetFileNfo(const FName: string; var Info: TFileInfo; NeedAttr: Boolean): Boolean;
function  GetFileNfoByHandle(Handle: Integer; var Info: TFileInfo): Boolean;
function  ZeroHandle(var Handle: Integer): Boolean;

function  _CreateFile(const FName: string; Mode: TCreateFileModeSet): Integer;
function  _CreateFileSecurity(const FName: string; Mode: TCreateFileModeSet; lpSecurityAttributes: PSecurityAttributes): Integer;
function  _GetFileSize(const FName: string): Integer;

function  DoCreateProcess(const s: string; var PI: TProcessInformation): Boolean;
function  ExecProcess(const Args; var PI: TProcessInformation; Env, Dir: Pointer; InheritHandles: Boolean): Boolean;
procedure FillStartupInfo(var SI: TStartupInfo);
function  SysErrorMsg(ErrorCode: Integer): string;

{ --- Registry Routines }

function  CreateRegKey(const AFName: string): Integer;
function  OpenRegKeyEx(const AName: string; AMode: Integer): Integer;
function  OpenRegKey(const AName: string): Integer;
function  ReadRegBin(Key: Integer; const rvn: string; Bin: Pointer; Sz: Integer): Boolean;
function  ReadRegInt(Key: Integer; const AStrName: string): Integer;
function  ReadRegString(Key: Integer; const AStrName: string): string;
function  WriteRegBin(Key: Integer; const rvn: string; Bin: Pointer; Sz: Integer): Boolean;
function  WriteRegInt(Key: Integer; const AStrName: string; AValue: Integer): Boolean;
function  WriteRegString(Key: Integer; const AStrName, AStr: string): Boolean;

{ --- Winsock tools }

function  AddrInet(i: Integer): string;
function  GetHostNameByAddr(Addr: Integer): string;
function  Inet2addr(const s: string): Integer;
function  InetAddr(const s: string): Integer;

{ --- Misc tools }

procedure GlobalFail;
function  _LogOK(const Name: string; var Handle: Integer): Boolean;
procedure xBaseDone;
procedure xBaseInit;
procedure uCvtSetFileTime(T: Integer; var L, H: Integer); assembler;
function uGetSystemTime: Integer;
function Vl(const s: string): Integer;

var
  TimeZoneBias: Integer;
  SocketsColl: TColl;

implementation


////////////////////////////////////////////////////////////////////////
//                                                                    //
//                          Time Routines                             //
//                                                                    //
////////////////////////////////////////////////////////////////////////



const
  cTimeHi   = 27111902;
  cTimeLo   = -717324288;
  cSecScale = 10000000;
  cAgeScale = 10000;

function uCvtGetFileTime(L, H: Integer): Integer; assembler;
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

function uCvtGetFileAge(L, H: Integer): Integer; assembler;
asm
  mov ecx, cAgeScale
  div ecx
end;


procedure uCvtSetFileTime(T: Integer; var L, H: Integer); assembler;
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


procedure uNix2WinTime(I: Integer; var T: TSystemTime);
var
  F: TFileTime;
begin
  uCvtSetFileTime(I, F.dwLowDateTime, F.dwHighDateTime);
  FileTimeToSystemTime(F, T);
end;

function uWin2NixTime(const T: TSystemTime): Integer;
var
  F: TFileTime;
begin
  SystemTimeToFileTime(T, F);
  Result := uCvtGetFileTime(F.dwLowDateTime, F.dwHighDateTime);
end;



function uGetLocalTime: Integer;
begin
  Result := uGetLocalTime;
end;

function uGetSystemTime: Integer;
var
  T: TFileTime;
begin
  GetSystemTimeAsFileTime(T);
  Result := uCvtGetFileTime(T.dwLowDateTime, T.dwHighDateTime);
end;

function uSetFileTimeByHandle(Handle: Integer; uTime: Integer): Boolean;
var
  F: TFileTime;
begin
  uCvtSetFileTime(uTime, F.dwLowDateTime, F.dwHighDateTime);
  Result := SetFileTime(Handle, nil, nil, @F);
end;

function uSetFileTime(const FName: string; uTime: Integer): Boolean;
var
  Handle: Integer;
begin
  Result := False;
  Handle := _CreateFile(FName, [cWrite, cExisting]);
  if Handle = INVALID_HANDLE_VALUE then Exit;
  Result := uSetFileTimeByHandle(Handle, uTime);
  CloseHandle(Handle);
end;

procedure CvtFD(const wf: TWin32FindData; var FindData: TuFindData);
begin
  FindData.Info.Attr := wf.dwFileAttributes;
  FindData.Info.Time := uCvtGetFileTime(wf.ftLastWriteTime.dwLowDateTime, wf.ftLastWriteTime.dwHighDateTime);
  FindData.Info.Size := wf.nFileSizeLow;
  FindData.FName := Buf2Str(wf.cFileName);
end;

function uFindFirst(const FName: string; var FindData: TuFindData): Integer;
var
  wf: TWin32FindData;
begin
  Result := FindFirstFile(PChar(FName), wf);
  if Result <> INVALID_HANDLE_VALUE then CvtFD(wf, FindData);
end;

function uFindNext(Handle: Integer; var FindData: TuFindData): Boolean;
var
  wf: TWin32FindData;
begin
  Result := FindNextFile(Handle, wf);
  if Result then CvtFD(wf, FindData);
end;

function uFindClose(Handle: Integer): Boolean;
begin
  Result := Windows.FindClose(Handle);
end;



////////////////////////////////////////////////////////////////////////
//                                                                    //
//                         string Routines                            //
//                                                                    //
////////////////////////////////////////////////////////////////////////


function IsWild(const S: string): Boolean;
begin
  Result := (Pos('*',S)>0) or (Pos('?', S)>0);
end;

function TrimZeros(S: string): string;
var
  I, J : Integer;
begin
  I := Length(S);
  while (I > 0) and (S[I] <= ' ') do
    Dec(I);
  J := 1;
  while (J < I) and ((S[J] <= ' ') or (S[J] = '0')) do
    Inc(J);
  TrimZeros := Copy(S, J, (I-J)+1);
end;

function BothKVC(const S: string): Boolean;
begin
  Result := (Copy(S, 1, 1)='"') and (Copy(S, Length(S), 1)='"');
end;

function AddRightSpaces;
begin
  SetLength(Result, NumSpaces);
  FillChar(Result[1], NumSpaces, ' ');
  Move(S[1], Result[1], Min(NumSpaces, Length(S)));
end;

function Hex2;
begin
  SetLength(Result, 2);
  Result[1] := rrLoHexChar[a shr 4];
  Result[2] := rrLoHexChar[a and $F];
end;

function Hex4;
  var I: Integer;
begin
  SetLength(Result, 4);
  for I := 0 to 3 do
    begin Result[4-I] := rrLoHexChar[A and $F]; A := A shr 4; end;
end;

function Hex8;
  var I: Integer;
begin
  SetLength(Result, 8);
  for I := 0 to 7 do
    begin Result[8-I] := rrLoHexChar[A and $F]; A := A shr 4; end;
end;

function Int2Hex(a: Integer): string;
begin
  Result := Hex8(a);
  while (Length(Result)>1) and (Result[1]='0') do DelFC(Result);
end;

function MakeFullDir(const D, S: string): string;
begin
  if (Pos(':', S) > 0) or (Copy(S, 1, 2) = '\\') then Result := S else
    if Copy(S, 1, 1) = '\' then Result := MakeNormName(Copy(D, 1, Pos(':',D)), Copy(S, 2, Length(S)-1)) else
      Result := MakeNormName(D,S);
end;

function ExtractDir;
var
  i: Integer;
begin
  Result := S; i := Length(S);
  if (i > 3) and (S[i] = '\') then DelLC(Result);
end;

function MakeNormName;
begin
  Result := Path;
  if (Result <> '') and (Result[Length(Result)] <> '\') then AddStr(Result, '\');
  Result := Result + Name;
end;

procedure AddStr;
begin
  S := S + C;
end;

procedure Add_Str(var S: ShortString ; C : char);
var
  sl: Byte absolute S;
begin
  Inc(sl); S[sl] := C;
end;

procedure FSplit(const FName: string; var Path, Name, Ext: string);
type
  TStep = (sExt, sName, sPath);
var
  Step : TStep;
  I: Integer;
  C: Char;
begin
  I := Length(FName);
  if Pos('.', FName) = 0 then Step := sName else Step := sExt;
  Path := ''; Name := ''; Ext  := '';
  while I > 0 do
  begin
    C := FName[I]; Dec(I);
    case Step of
      sExt  : begin Ext := C + Ext; if C = '.' then Inc(Step) end;
      sName : if C = '\' then begin Path := C; Inc(Step) end else Name := C + Name;
      sPath : Path := C + Path;
    end;
  end;
end;


function Replace;
 var I, J: Integer;
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
    Delete(S, J+I-1, LP);
    Insert(ReplaceString, S, J+I-1);
    Result := True;
   end;
  Inc(J, I + LR - 1);
 until I = 0;
end;

procedure DelDoubles;
var
  i: Integer;
begin
  repeat
    i := Pos(ST,Source);
    if i = 0 then Break;
    Delete(Source,I,1);
  until False;
end;

function ItoS(I: Integer): string;
begin
  Str(I, Result);
end;

function ItoSz(I, Width: Integer): string;
begin
  Result := ItoS(I);
  while Length(Result)<Width do Result := '0'+Result;
end;

function DelLeft(const S: string): string;
var
  I, L: Integer;
begin
  I := 1;
  L := Length(S);
  while I<=L do
  begin
    case S[I] of #9, ' ':; else Break end;
    Inc(I);
  end;
  Result := Copy(S, I, L+1-I);
end;

function DelRight(const S: string): string;
var
  I: Integer;
begin
  I := Length(S);
  while I>0 do
  begin
    case S[I] of #9, ' ':; else Break end;
    Dec(I);
  end;
  Result := Copy(S, 1, I);
end;

function DelSpaces(const s: string): string;
begin
  Result := DelLeft(DelRight(s));
end;

procedure DelFC(var s: string);
begin
  Delete(s, 1, 1);
end;

procedure DelLC(var s: string);
var
  l: Integer;
begin
  l := Length(s);
  case l of
    0 : ;
    1 : s := '';
    else SetLength(s, l-1);
  end;
end;

function Int2Str(L: Integer): string;
var I: Integer;
begin
  Result := ItoS(L);
  I := Length(Result)-2;
  while I > 1 do
    begin
      Insert(','{ThousandSeparator}, Result, I);
      Dec(I, 3);
    end;
end;

function ExtractFileRoot(const FileName: string): string;
begin
  Result := Copy(FileName, 1, Pos(':',FileName)+1);
end;

function WipeChars;
var
  i, j: Integer;
begin
  Result := ''; j := Length(AStr);
  for i := 1 to j do if Pos(AStr[I], AWipeChars) = 0 then AddStr(Result, AStr[I]);
end;

procedure FillCharSet(const AStr: string; var CharSet: TCharSet);
var
  i: Integer;
begin
  CharSet := [];
  for i := 1 to Length(AStr) do Include(CharSet, AStr[i]);
end;

function DigitsOnly(const AStr: string): Boolean;
var
  i: Integer;
begin
  Result := False;
  if AStr = '' then Exit;
  for i := 1 to Length(AStr) do if not __digit(AStr[i]) then Exit;
  Result := True;
end;

procedure GetWrd(var s,w:string;c:char);
begin
 w:=''; if s='' then Exit;
 if c = ' ' then s := DelSpaces(s);
 while (Length(s)>0) and (s[1]<>c) do begin w:=w+s[1];DelFC(s) end;
 DelFC(s);
end;

procedure GetWrdStrict(var s,w:string);
begin
  w:=''; if s='' then Exit;
  while (Length(s)>0) and (s[1]<>' ') do begin w:=w+s[1];DelFC(s) end;
  DelFC(s);
end;

procedure GetWrdStrictUC(var s,w:string);
begin
  w:=''; if s='' then Exit;
  while (Length(s)>0) and (s[1]<>' ') do begin w:=w+UpCase(s[1]);DelFC(s) end;
  DelFC(s);
end;

function StrRight(const S: string; Num: Integer): string;
begin
  Result := Copy(S, Length(S)-Num+1, Num);
end;

function StrEnds(const S1, S2: string): Boolean;
begin
  Result := StrRight(S1, Length(S2)) = S2;
end;

function CopyLeft(const S: string; I: Integer): string;
begin
  Result := Copy(S, I, Length(S)-I+1);
end;

procedure DeleteLeft(var S: string; I: Integer);
begin
  Delete(S, I, Length(S)-I+1);
end;


////////////////////////////////////////////////////////////////////////
//                                                                    //
//                          Basic Routines                            //
//                                                                    //
////////////////////////////////////////////////////////////////////////

procedure Clear(var Buf; Count: Integer);
begin
  FillChar(Buf, Count, 0);
end;

function MemEqu(const A, B; Sz: Integer): Boolean;
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

function Max(A, B: Integer): Integer;
asm
  cmp  eax, edx
  jg   @@g
  xchg eax, edx
@@g:
end;


function Min(A, B: Integer): Integer; assembler;
asm
  cmp  eax, edx
  jl   @@l
  xchg eax, edx
@@l:
end;

procedure XChg(var Critical, Normal: Integer); assembler;
asm
  mov  ecx, [edx]
  xchg [eax], ecx
  mov  [edx], ecx
end;

function NulSearch; assembler;
asm;
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

function Buf2Str(const Buffer): string;
var
  I: Integer;
begin
  I := NulSearch(Buffer);
  SetLength(Result, I);
  Move(Buffer, Result[1], I);
end;

procedure LowerPrec(var A, B: Integer; Bits: Byte);
var
  C: ShortInt;
begin
  C := Max(NumBits(A), NumBits(B))-Bits;
  if C <= 0 then Exit;
  A := A shr C;
  B := B shr C;
end;



////////////////////////////////////////////////////////////////////////
//                                                                    //
//                      Win32 Events Extentions                       //
//                                                                    //
////////////////////////////////////////////////////////////////////////



function CreateEvtA;
begin
  Result := CreateEvent(nil, False, False, nil);
end;

function CreateEvt;
begin
  CreateEvt := CreateEvent(nil,      // address of security attributes
                           True,     // flag for manual-reset event
                           Initial,  // flag for initial state
                           nil);     // address of event-object name
end;

function  WaitEvtA(nCount: Integer; lpHandles: PWOHandleArray; Timeout: Integer): Integer;
begin
  if Timeout = MaxInt then Timeout := INFINITE;
  if nCount = 1 then Result := WaitForSingleObject(lpHandles^[0], Timeout) else
                     Result := WaitForMultipleObjects(nCount, lpHandles, False, Timeout);
end;

function WaitEvt;
begin
  Result := WaitEvtA(High(id)+1, @id, Timeout);
end;

function SignaledEvt(id: Integer): Boolean;
begin
  SignaledEvt := WaitForSingleObject(id, 0) = id;
end;


////////////////////////////////////////////////////////////////////////
//                                                                    //
//                      Win32 API Hooks                               //
//                                                                    //
////////////////////////////////////////////////////////////////////////

procedure CloseHandles(const Handles: array of Integer);
var
  i: Integer;
begin
  for i:=0 to High(Handles) do CloseHandle(Handles[i]);
end;

function FileExists(const FName: string): Boolean;
var
  Handle: Integer;
begin
  Result := False;
  Handle := _CreateFile(FName, [cRead, cShareAllowWrite]);
  if Handle = INVALID_HANDLE_VALUE then Exit;
  Result := ZeroHandle(Handle);
end;

function GetFileNfo;
var
  Handle: Integer;
begin
  Result := False;
  Handle := _CreateFile(FName, [cRead, cShareAllowWrite]);
  if Handle = INVALID_HANDLE_VALUE then Exit;
  Result := GetFileNfoByHandle(Handle, Info);
  CloseHandle(Handle);
  if NeedAttr and Result and (Info.Attr = -1) then Result := GetFileAttributes(PChar(FName)) <> -1;
end;

function GetFileNfoByHandle;
var
  i: TByHandleFileInformation;
begin
  Result := False;
  if Handle = INVALID_HANDLE_VALUE then Exit;
  if True then
  begin
    i.dwFileAttributes := -1;
    i.nFileSizeLow := GetFileSize(Handle, nil);
    Result := (i.nFileSizeLow <> -1) and GetFileTime(Handle, nil, nil, @i.ftLastWriteTime);
  end else
  begin
    Result := Windows.GetFileInformationByHandle(Handle, i);
  end;
  if not Result then Exit;
  Info.Size := i.nFileSizeLow;
  Info.Attr := i.dwFileAttributes;
  Info.Time := uCvtGetFileTime(i.ftLastWriteTime.dwLowDateTime, i.ftLastWriteTime.dwHighDateTime);
  Result := True;
end;


function ClearHandle(var Handle: Integer): Boolean;
begin
  if Handle = INVALID_HANDLE_VALUE then Result := False else
  begin
    Result := CloseHandle(Handle);
    Handle := INVALID_HANDLE_VALUE;
  end;
end;

function ZeroHandle(var Handle: Integer): Boolean;
begin
  if (Handle = INVALID_HANDLE_VALUE) or
     (Handle = 0) then Result := False else
  begin
    Result := CloseHandle(Handle);
    Handle := 0;
  end;
end;

procedure _PostMessage(a, b, c, d: Integer);
begin
  if not PostMessage(a, b, c, d) then
    GlobalFail;
end;

function _CreateFile;
begin
  Result := _CreateFileSecurity(FName, Mode, nil);
end;

function _CreateFileSecurity;
var
  Access,Share,Disp,Flags: Integer;

const
  NumDispModes = 5;
  DispArr : array[1..NumDispModes] of
    record
      w: Boolean; {Write}
      n: Boolean; {EnsureNew}
      t: Boolean; {Truncate}
      d: Integer; {Disp}
    end =
     ( (w:False; n:False; t:False; d:OPEN_EXISTING),
       (w:True;  n:False; t:False; d:OPEN_ALWAYS),
       (w:True;  n:True;  t:False; d:CREATE_NEW),
       (w:True;  n:False; t:True;  d:CREATE_ALWAYS),
       (w:True;  n:True;  t:True;  d:TRUNCATE_EXISTING) );
begin

// Prepare Disp & Flags

  Flags := FILE_ATTRIBUTE_NORMAL;
  Access := 0;
  Share := 0;
  Disp := 0;

  if cFlag in Mode then
  begin
    Disp := CREATE_NEW;
    Flags := Flags or FILE_FLAG_DELETE_ON_CLOSE
  end else
  begin

    if cTruncate in Mode then Mode := Mode + [cWrite];

    if cExisting in Mode then Disp := OPEN_EXISTING else
    begin
      if cWrite in Mode then Flags := FILE_ATTRIBUTE_ARCHIVE;
      repeat
        Inc(Disp); if Disp > NumDispModes then GlobalFail;
        with DispArr[Disp] do
        if (w = (cWrite in Mode)) and
           (n = (cEnsureNew in Mode)) and
           (t = (cTruncate in Mode)) then begin Disp := d; Break end;
      until False;

    end;

    if cOverlapped in Mode then Flags := Flags or FILE_FLAG_OVERLAPPED;
    if cRandomAccess in Mode then Flags := Flags or FILE_FLAG_RANDOM_ACCESS;
    if cSequentialScan in Mode then Flags := Flags or FILE_FLAG_SEQUENTIAL_SCAN;
    if cDeleteOnClose in Mode then Flags := Flags or FILE_FLAG_DELETE_ON_CLOSE;


  // Prepare 'Access' and 'Share'

    if cShareAllowWrite in Mode then Share := FILE_SHARE_WRITE;
    if cRead  in Mode then begin Access := Access or GENERIC_READ;  Share := Share or FILE_SHARE_READ end;
    if cWrite in Mode then begin Access := Access or GENERIC_WRITE; Share := Share or FILE_SHARE_READ end;
    if cShareDenyRead in Mode then Share := Share and not FILE_SHARE_READ;
  end;

  Result := CreateFile(PChar(FName), Access, Share, lpSecurityAttributes, Disp, Flags, 0);
end;


function _GetFileSize;
var
  H: Integer;
begin
  Result := -1;
  H := _CreateFile(FName, [cRead]);
  if H = INVALID_HANDLE_VALUE then Exit;
  Result := GetFileSize(H, nil);
  CloseHandle(H);
end;




function WindowsDirectory: string;
begin
  SetLength(Result, MAX_PATH);
  GetWindowsDirectory(PChar(Result), MAX_PATH);
  SetLength(Result, NulSearch(Result[1]));
end;


function ExecProcess;
var
  SI: TStartupInfo;
begin
  FillStartupInfo(SI);
  Result := CreateProcess(
    nil,                     // pointer to name of executable module
    PChar(Args),             // pointer to command line string
    nil,                     // pointer to process security attributes
    nil,                     // pointer to thread security attributes
    InheritHandles,          // handle inheritance flag
    NORMAL_PRIORITY_CLASS or
    CREATE_SUSPENDED,        // creation flags
    env,                     // pointer to new environment block
    Dir,                     // pointer to current directory name
    SI,                      // pointer to STARTUPINFO
    PI                       // pointer to PROCESS_INFORMATION
  );
end;



////////////////////////////////////////////////////////////////////////
//                                                                    //
//                      Registry Routines                             //
//                                                                    //
////////////////////////////////////////////////////////////////////////

function OpenRegKeyEx(const AName: string; AMode: Integer): Integer;
begin
  if RegOpenKeyEx(
    HKEY_LOCAL_MACHINE,      // handle of an open key
    PChar(AName),           // subkey name
    0,                       // Reserved
    AMode,
    Result
  ) <> ERROR_SUCCESS then Result := -1;
end;

function OpenRegKey(const AName: string): Integer;
begin
  Result := OpenRegKeyEx(AName, KEY_QUERY_VALUE);
end;

function CreateRegKey(const AFName: string): Integer;
var
  Disp: Integer;
begin
  if RegCreateKeyEx(
    HKEY_LOCAL_MACHINE,      // handle of an open key
    PChar(AFName),           // subkey name
    0,                       // reserved, must be zero
    nil,                     // address of class string
    REG_OPTION_NON_VOLATILE, // options flag
    KEY_WRITE,               // desired security access
    nil,                     // security attributes
    Result,                  // address of buffer for opened handle
    @Disp                    // address of disposition value buffer
  ) <> ERROR_SUCCESS then begin
    Result := -1;
  end;

end;

function WriteRegString(Key: Integer; const AStrName, AStr: string): Boolean;
begin
  Result := RegSetValueEx(Key, PChar(AStrName), 0, REG_SZ, PChar(AStr), Length(AStr)+1) = ERROR_SUCCESS;
end;


function ReadRegString(Key: Integer; const AStrName: string): string;
var
  l, t,e: Integer;
  z: ShortString;
begin
  z[0] := #250;
  l := 250;
  t := REG_SZ;
  e := RegQueryValueEx(
    Key,             // handle of key to query
    PChar(AStrName), // value to query
    nil,             // reserved
    @t,              // value type
    @z[1],           // data buffer
    @l               // buffer size
  );
  if e <> ERROR_SUCCESS then Result := '' else
  begin
    Result := Copy(z, 1, NulSearch(z[1]));
  end;
end;

function WriteRegInt(Key: Integer; const AStrName: string; AValue: Integer): Boolean;
begin
  Result := RegSetValueEx(Key, PChar(AStrName), 0, REG_DWORD, @AValue, SizeOf(AValue)) = ERROR_SUCCESS;
end;

function ReadRegInt(Key: Integer; const AStrName: string): Integer;
var
  t, e, b, s: Integer;
begin
  t := REG_DWORD;;
  s := SizeOf(b);
  e := RegQueryValueEx(
    Key,             // handle of key to query
    PChar(AStrName), // value to query
    nil,             // reserved
    @t,              // value type
    @b,              // data buffer
    @s               // buffer size
  );
  if e <> ERROR_SUCCESS then Result := -1 else Result := b;
end;

function WriteRegBin(Key: Integer; const rvn: string; Bin: Pointer; Sz: Integer): Boolean;
begin
  Result := RegSetValueEx(Key, PChar(rvn), 0, REG_BINARY, Bin, Sz) = ERROR_SUCCESS;
end;

function ReadRegBin(Key: Integer; const rvn: string; Bin: Pointer; Sz: Integer): Boolean;
var
  t, e, s: Integer;
begin
  t := REG_BINARY;;
  s := Sz;
  e := RegQueryValueEx(
    Key,             // handle of key to query
    PChar(rvn),      // value to query
    nil,             // reserved
    @t,              // value type
    Bin,             // data buffer
    @s               // buffer size
  );
  Result := e = ERROR_SUCCESS;
end;

////////////////////////////////////////////////////////////////////////
//                                                                    //
//                             Objects                                //
//                                                                    //
////////////////////////////////////////////////////////////////////////


function SysErrorMsg(ErrorCode: Integer): string;
var
  Len: Integer;
  Buffer: array[0..255] of Char;
begin
  Len := FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM or
    FORMAT_MESSAGE_ARGUMENT_ARRAY, nil, ErrorCode, 0, Buffer,
    SizeOf(Buffer), nil);
  while (Len > 0) and (Buffer[Len - 1] in [#0..#32, '.']) do Dec(Len);
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
      while SCompare(SortList^[I], P) < 0 do Inc(I);
      while SCompare(SortList^[J], P) > 0 do Dec(J);
      if I <= J then
      begin
        T := SortList^[I];
        SortList^[I] := SortList^[J];
        SortList^[J] := T;
        Inc(I);
        Dec(J);
      end;
    until I > J;
    if L < J then QuickSort(SortList, L, J, SCompare);
    L := I;
  until I >= R;
end;


{ ---- TColl ---- }

procedure TColl.Sort(Compare: TListSortCompare);
begin
  if (FList <> nil) and (Count > 0) then
    QuickSort(FList, 0, Count - 1, Compare);
end;


function TColl.Copy;
begin
  Result := TColl.Create;
  CopyItemsTo(TColl(Result));
end;

procedure TColl.CopyItemsTo;
var
  i: Integer;
begin
  Coll.FreeAll;
  for i := 0 to Count-1 do Coll.AtInsert(Coll.Count, CopyItem(At(i)));
end;

function TColl.CopyItem(AItem: Pointer): Pointer;
begin
  Result := TAdvCpObject(AItem).Copy;
end;

procedure TColl.Concat(AColl: TColl);
var
  i: Integer;
begin
  for i := 0 to AColl.Count-1 do Insert(AColl[i]);
  AColl.DeleteAll;
end;


procedure TColl.Enter;
var
  j: Integer;
begin
  j := 1; Xchg(Shared, j); if j = 0 then InitializeCriticalSection(CS);
  EnterCriticalSection(CS);
end;

procedure TColl.Leave;
begin
  LeaveCriticalSection(CS);
end;

procedure TColl.ForEach(Proc: TForEachProc);
var
  i: Integer;
begin
  for i := 0 to Count-1 do Proc(FList^[I]);
end;

constructor TColl.Create;
begin
  inherited Create;
  DoInit(32,64);
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
  if Shared = 1 then DeleteCriticalSection(CS);
  FreeAll;
  SetCapacity(0);
  inherited Destroy;
end;

function TColl.At(Index: Integer): Pointer;
begin
  if (Index < 0) or (Index >= FCount) then GlobalFail;
  Result := FList^[Index];
end;


procedure TColl.AtDelete(Index: Integer);
begin
  if (Index < 0) or (Index >= FCount) then GlobalFail;
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
  if (Index < 0) or (Index > FCount) then GlobalFail;
  if FCount = FCapacity then SetCapacity(FCapacity + FDelta);
  if Index < FCount then
    System.Move(FList^[Index], FList^[Index + 1],
      (FCount - Index) * SizeOf(Pointer));
  FList^[Index] := Item;
  Inc(FCount);
end;

procedure TColl.AtPut(Index: Integer; Item: Pointer);
begin
  if (Index < 0) or (Index >= FCount) then GlobalFail;
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
  for I := 0 to FCount - 1 do FreeItem(At(I));
  FCount := 0;
end;

procedure TColl.FreeItem(Item: Pointer);
begin
  TObject(Item).Free;
end;

function TColl.IndexOf(Item: Pointer): Integer;
begin
  Result := 0;
  while (Result < FCount) and (FList^[Result] <> Item) do Inc(Result);
  if Result = FCount then Result := -1;
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
  for I := FCount - 1 downto 0 do if Items[I] = nil then AtDelete(I);
end;

procedure TColl.SetCapacity;
begin
  if (NewCapacity < FCount) or (NewCapacity > MaxCollSize) then GlobalFail;
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
    if (NewIndex < 0) or (NewIndex >= FCount) then GlobalFail;
    Item := FList^[CurIndex];
    AtDelete(CurIndex);
    AtInsert(NewIndex, Item);
  end;
end;

{ TSortedColl }

function TSortedColl.KeyOf;
begin
  Result := Item;
end;

function TSortedColl.IndexOf(Item: Pointer): Integer;
var
  I: Integer;
begin
  IndexOf := -1;
  if Search(KeyOf(Item), I) then
  begin
    if Duplicates then
      while (I < Count) and (Item <> FList^[I]) do Inc(I);
    if I < Count then IndexOf := I;
  end;
end;

procedure TSortedColl.Insert(Item: Pointer);
var
  I: Integer;
begin
  if not Search(KeyOf(Item), I) or Duplicates then AtInsert(I, Item);
end;

function TSortedColl.Search(Key: Pointer; var Index: Integer): Boolean;
var
  L, H, I, C: Integer;
begin
  Search := False;
  L := 0;
  H := Count - 1;
  while L <= H do
  begin
    I := (L + H) shr 1;
    C := Compare(KeyOf(FList^[I]), Key);
    if C < 0 then L := I + 1 else
    begin
      H := I - 1;
      if C = 0 then
      begin
        Search := True;
        if not Duplicates then L := I;
      end;
    end;
  end;
  Index := L;
end;

{ TStringColl }

function TStringColl.LongString: string;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to Count-1 do Result := Result + Strings[i] + #13#10;
end;

function TStringColl.LongStringD(c: char): string;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to Count-2 do Result := Result + Strings[i] + c;
  for i := Max(0, Count-1) to Count-1 do Result := Result + Strings[i];
end;

procedure TStringColl.FillEnum(Str: string; Delim: Char; Sorted: Boolean);
var
  Z: string;
begin
  while Str <> '' do
  begin
    GetWrd(Str, Z, Delim);
    if Sorted then Ins(Z) else Add(Z);
  end;
end;


function TStringColl.Found(const Str: string): Boolean;
var
  i: Integer;
begin
  Result := Search(@Str, I);
end;

function TStringColl.FoundU(const Str: string): Boolean;
var
  i: Integer;
begin
  Result := False;
  for i := 0 to Count-1 do if Str = Strings[i] then begin Result := True; Exit end;
end;

function TStringColl.FoundUC(const Str: string): Boolean;
var
  us: string;
  i: Integer;
begin
  us := UpperCase(Str);
  Result := False;
  for i := 0 to Count-1 do if us = UpperCase(Strings[i]) then begin Result := True; Exit end;
end;

function TStringColl.Copy;
begin
  Result := TStringColl.Create;
  CopyItemsTo(TColl(Result));
end;

function TStringColl.CopyItem(AItem: Pointer): Pointer;
begin
  Result := NewStr(PString(AItem)^);
end;


function TStringColl.KeyOf(Item: Pointer): Pointer;
begin
  KeyOf := Item;
end;

procedure TStringColl.Concat(AColl: TStringColl);
var
  i: Integer;
begin
  for i := 0 to AColl.Count - 1 do AtInsert(Count, AColl.At(I));
  AColl.DeleteAll;
end;

procedure TStringColl.AppendTo(AColl: TStringColl);
var
  i: Integer;
begin
  for i := 0 to Count - 1 do AColl.Add(Strings[i]);
end;

procedure TStringColl.Fill(const AStrs: array of string);
var
  i: Integer;
begin
  FreeAll;
  for i := Low(AStrs) to High(AStrs) do Add(AStrs[i]);
end;

procedure TStringColl.AddStrings(Strings: TStringColl; Sort: Boolean);
var
  i: Integer;
begin
  for i := 0 to Strings.Count-1 do
    if Sort then Ins(Strings[i]) else Add(Strings[i]);
end;

function TStringColl.IdxOf(Item: string): Integer;
begin
  Result := IndexOf(@Item);
end;

procedure TStringColl.SetString(Index: Integer; const Value: string);
begin
  FreeItem(At(Index));
  AtPut(Index, NewStr(Value));
end;

function TStringColl.GetString(Index: Integer): string;
begin
  Result := PString(At(Index))^;
end;

function TStringColl.Compare(Key1, Key2: Pointer): Integer;
begin
  Compare := CompareStr(PString(Key1)^, PString(Key2)^);
end;

procedure TStringColl.FreeItem(Item: Pointer);
begin
  DisposeStr(Item);
end;

procedure TStringColl.AtIns(Index: Integer; const Item: string);
begin
  AtInsert(Index, NewStr(Item));
end;

procedure TStringColl.Add(const S: string);
begin
  AtInsert(Count, NewStr(S));
end;

procedure TStringColl.Ins0(const S: string);
begin
  AtInsert(0, NewStr(S));
end;

procedure TStringColl.Ins(const S: string);
begin
  Insert(NewStr(S));
end;

procedure FreeObject(var O);
var
  OO: TObject absolute O;
  OP: Pointer absolute O;
begin
  if OP <> nil then begin OO.Free; OP := nil end;
end;

function DeleteEmptyDirInheritance(S: string; const StopOn: string): Integer;
begin
  Result := 0;
  while (S <> StopOn) and RemoveDirectory(PChar(S)) do
  begin
    Inc(Result);
    S := ExtractFileDir(S);
  end;
end;

const
  CMonths = 'JanFebMarAprMayJunJulAugSepOctNovDec';
  Months: string[Length(CMonths)] = CMonths;

function MonthE(m: Integer): string;
begin
  Result := Copy(Months, 1+(m-1)*3, 3);
end;


procedure GlobalFail;
begin
//  WriteLn('Global Failure!!!');
  Halt;
end;


function CompareMask(const n, m: string; SupportPercent: Boolean): Boolean;
var
  i: Integer;
begin
  Result := False;
  for i := 1 to Length(m) do
  begin
    if (m[i] = '?') then Continue;
    if (i > Length(n)) or (n[i] <> m[i]) then
    begin
      if SupportPercent and (m[i] = '%') and (n[i] in ['0'..'9']) then else Exit;
    end;
  end;
  Result := True;
end;

function PosMask(const m, s: string; SupportPercent: Boolean): Integer;
var
  i: Integer;
begin
  Result := 0;
  for i := 1 to Length(s)-Length(m)+1 do
  begin
    if CompareMask(Copy(s, i, Length(m)), m, SupportPercent) then
    begin
      Result := i;
      Exit;
    end;
  end;
end;

function CreateTCollEL: TColl;
begin
  Result := TColl.Create;
  TColl(Result).Enter;
  TColl(Result).Leave;
end;

procedure XorStr(P: PByteArray; Len: Integer; const S: string);
var
  sl, i: Integer;
begin
  sl := Length(s); if sl = 0 then Exit;
  for i := 0 to Len-1 do
  begin
    P^[i] := P^[i] xor Byte(S[(i mod sl)+1]);
  end;
end;

function GetEnvVariable(const Name: string): string;
const
  BufSize = 128;
var
  Buf: array[0..BufSize] of Char;
  I: Integer;
begin
  I := GetEnvironmentVariable(PChar(Name), Buf, BufSize);
  case I of
    1..BufSize:
      begin
        SetLength(Result, I);
        Move(Buf, Result[1], I);
      end;
    BufSize+1..MaxInt:
      begin
        SetLength(Result, I+1);
        GetEnvironmentVariable(PChar(Name), @Result[1], I);
        SetLength(Result, I);
      end;
    else
      begin
        Result := '';
      end;
   end;
end;

function LoadRS(Ident: Integer): string;
const
   strbufsize = $10000;
var
   strbuf: array[0..StrBufSize] of Char;
begin
  SetString(Result, PChar(@strbuf), LoadString(hInstance, Ident, @strbuf, strbufsize));
end;

function StrBegins(const s1,s2:string):Boolean;
begin
  Result := Copy(s1, 1, Length(s2)) = s2;
end;

function DivideDash(const S: string): string;
begin
  Result := S;
  Insert('-', Result, (Length(S) div 2)+1);
end;

procedure FillStartupInfo(var SI: TStartupInfo);
begin
  SI.CB := SizeOf(SI);
  SI.lpReserved := nil;
  SI.lpDesktop := nil;
  SI.lpTitle := nil;
  SI.dwFlags := STARTF_USESHOWWINDOW;
  SI.wShowWindow := SW_MINIMIZE;
  SI.cbReserved2 := 0;
  SI.lpReserved2 := nil;
end;

procedure MoveColl(Src, Dst: TColl; Idx: Integer);
begin
  if Idx = -1 then Exit;
  Dst.Insert(Src[Idx]);
  Src.AtDelete(Idx);
end;


function TempFileName(const APath, APfx: string): string;
var
  s: string;
begin
  SetLength(s, 1000);
  GetTempFileName(PChar(APath), PChar(APfx), 0, @s[1]);
  Result := Copy(s, 1, NulSearch(s[1]));
end;

function CreateTempFile(const APath, APfx: string; var FName: string): Integer;
begin
  FName := TempFileName(APath, APfx);
  Result := _CreateFile(FName, [cWrite, cExisting]);
end;

(*
utils
d:\bd\source\rtl\win\windows.pas
d:\bd\source\rtl\win\messages.pas
d:\bd\source\vcl\classes
f:\xvcl\comctrls
d:\bd\source\rtl\win\shellapi
d:\bd\source\rtl\sys\sysutils
*)


function DoCreateProcess(const s: string; var PI: TProcessInformation): Boolean;
var
  SI: TStartupInfo;
begin
  FillStartupInfo(SI);
  Result := CreateProcess(
    nil,                     // pointer to name of executable module
    PChar(s),                // pointer to command line string
    nil,                     // pointer to process security attributes
    nil,                     // pointer to thread security attributes
    False,                   // handle inheritance flag
    CREATE_SUSPENDED,        // creation flags
    nil,                     // pointer to new environment block
    nil,                     // pointer to current directory name
    SI,                      // pointer to STARTUPINFO
    PI                       // pointer to PROCESS_INFORMATION
  );
end;


{ TThread }

function ThreadProc(Thread: TThread): Integer;
var
  FreeThread: Boolean;
begin
  Thread.Execute;
  FreeThread := Thread.FFreeOnTerminate;
  Result := Thread.FReturnValue;
  Thread.FFinished := True;
  if FreeThread then Thread.Free;
  EndThread(Result);
end;

constructor TThread.Create(CreateSuspended: Boolean);
var
  Flags: Integer;
begin
  inherited Create;
  FSuspended := CreateSuspended;
  Flags := 0;
  if CreateSuspended then Flags := CREATE_SUSPENDED;
  FHandle := BeginThread(nil, 0, @ThreadProc, Pointer(Self), Flags, FThreadID);
end;

destructor TThread.Destroy;
begin
  if FHandle <> 0 then CloseHandle(FHandle);
  inherited Destroy;
end;

const
  Priorities: array [TThreadPriority] of Integer =
   (THREAD_PRIORITY_IDLE, THREAD_PRIORITY_LOWEST, THREAD_PRIORITY_BELOW_NORMAL,
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
    if Priorities[I] = P then Result := I;
end;

procedure TThread.SetPriority(Value: TThreadPriority);
begin
  SetThreadPriority(FHandle, Priorities[Value]);
end;

procedure TThread.SetSuspended(Value: Boolean);
begin
  if Value <> FSuspended then
    if Value then
      Suspend else
      Resume;
end;

procedure TThread.Suspend;
begin
  FSuspended := True;
  SuspendThread(FHandle);
end;

procedure TThread.Resume;
begin
  if ResumeThread(FHandle) = 1 then FSuspended := False;
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



function ExtractFilePath(const FileName: string): string;
var
  I: Integer;
begin
  I := LastDelimiter('\:', FileName);
  Result := Copy(FileName, 1, I);
end;

function ExtractFileDir(const FileName: string): string;
var
  I: Integer;
begin
  I := LastDelimiter('\:',Filename);
  if (I > 1) and (FileName[I] = '\') and
    (not (FileName[I - 1] in ['\', ':'])) then Dec(I);
  Result := Copy(FileName, 1, I);
end;

function ExtractFileDrive(const FileName: string): string;
var
  I, J: Integer;
begin
  if (Length(FileName) >= 2) and (FileName[2] = ':') then
    Result := Copy(FileName, 1, 2)
  else if (Length(FileName) >= 2) and (FileName[1] = '\') and
    (FileName[2] = '\') then
  begin
    J := 0;
    I := 3;
    While (I < Length(FileName)) and (J < 2) do
    begin
      if FileName[I] = '\' then Inc(J);
      if J < 2 then Inc(I);
    end;
    if FileName[I] = '\' then Dec(I);
    Result := Copy(FileName, 1, I);
  end else Result := '';
end;

function LastDelimiter(const Delimiters, S: string): Integer;
begin
  Result := Length(S);
  while Result > 0 do
  begin
    if (S[Result] <> #0) and (Pos(S[Result], Delimiters) = 0) then Dec(Result) else Break;
  end;
end;

function ExtractFileName(const FileName: string): string;
var
  I: Integer;
begin
  I := LastDelimiter('\:', FileName);
  Result := Copy(FileName, I + 1, MaxInt);
end;

function ExtractFileExt(const FileName: string): string;
var
  I: Integer;
begin
  I := LastDelimiter('.\:', FileName);
  if (I > 0) and (FileName[I] = '.') then
    Result := Copy(FileName, I, MaxInt) else
    Result := '';
end;

function ExpandFileName(const FileName: string): string;
var
  FName: PChar;
  Buffer: array[0..MAX_PATH - 1] of Char;
begin
  SetString(Result, Buffer, GetFullPathName(PChar(FileName), SizeOf(Buffer),
    Buffer, FName));
end;


function UpperCase(const S: string): string;
var
  Ch: Char;
  L: Integer;
  Source, Dest: PChar;
begin
  L := Length(S);
  SetLength(Result, L);
  Source := Pointer(S);
  Dest := Pointer(Result);
  while L <> 0 do
  begin
    Ch := Source^;
    if (Ch >= 'a') and (Ch <= 'z') then Dec(Ch, 32);
    Dest^ := Ch;
    Inc(Source);
    Inc(Dest);
    Dec(L);
  end;
end;

function LowerCase(const S: string): string;
var
  Ch: Char;
  L: Integer;
  Source, Dest: PChar;
begin
  L := Length(S);
  SetLength(Result, L);
  Source := Pointer(S);
  Dest := Pointer(Result);
  while L <> 0 do
  begin
    Ch := Source^;
    if (Ch >= 'A') and (Ch <= 'Z') then Inc(Ch, 32);
    Dest^ := Ch;
    Inc(Source);
    Inc(Dest);
    Dec(L);
  end;
end;

const
  EmptyStr: string = '';
  NullStr: PString = @EmptyStr;

function NewStr(const S: string): PString;
begin
  if S = '' then Result := NullStr else
  begin
    New(Result);
    Result^ := S;
  end;
end;

procedure DisposeStr(P: PString);
begin
  if (P <> nil) and (P^ <> '') then Dispose(P);
end;

function CompareStr(const S1, S2: string): Integer; assembler;
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
  if Registered then SocketsColl.Delete(Self);
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
  inherited Destroy;
end;

function TSocket.Read(var B; Size: Integer): Integer;
begin
  Result := _Read(B, Size);
  Dead := 0;
end;

function TSocket.Write(const B; Size: Integer): Integer;
begin
  Result := _Write(B, Size);
  Dead := 0;
end;



function TSocket.WriteStr(const s: string): Integer;
begin
  Result := Write(s[1], Length(s));
end;

function TSocket._Write(const B; Size: Integer): Integer;
var
  I: Integer;
begin
  I := send(Handle, (@B)^, Size, 0);
  if I = SOCKET_ERROR then Status := WSAGetLastError;
  Result := I;
end;

function TSocket._Read(var B; Size: Integer): Integer;
begin
  Result := recv(Handle, B, Size, 0);
  if Result = SOCKET_ERROR then Status := WSAGetLastError;
end;

function Inet2addr(const s: string): Integer;
begin
  Result := inet_addr(PChar(s));
end;

function __pchar(c: char): Boolean;
begin
  case c of
    ':', '@', '&', '=', '+': Result := True
    else Result := __uchar(c)
  end;
end;

function __uchar(c: char): Boolean;
begin
  Result := __alpha(c) or __digit(c) or __safe(c) or __extra(c) or __national(c)
end;

function __national(c: char): Boolean;
begin
  case c of
    '0'..'9', 'A'..'Z', 'a'..'z': Result := False;
    else Result := not (__reserved(c) or __extra(c) or __safe(c) or __unsafe(c));
  end;
end;

function __reserved(c: char): Boolean;
begin
  case c of
    ';', '/', '?', ':', '@', '&', '=', '+' : Result := True
    else Result := False;
  end;
end;

function __extra(c: char): Boolean;
begin
  case c of
    '!', '*', '''' ,'(', ')', ',' : Result := True
    else Result := False;
  end;
end;

function __safe(c: char): Boolean;
begin
  case c of
    '$', '-', '_', '.' : Result := True
    else Result := False;
  end;
end;

function __unsafe(c: char): Boolean;
begin
  case c of
      '"', '#', '%', '<', '>': Result := True;
    else Result := __ctl(c);
  end;
end;

function __alpha(c: char): Boolean;
begin
  case c of
    'A'..'Z', 'a'..'z': Result := True
    else Result := False;
  end;
end;

function __digit(c: char): Boolean;
begin
  case c of
    '0'..'9': Result := True
    else Result := False;
  end;
end;

function __ctl(c: char): Boolean;
begin
  case c of
    #0..#31, #127 : Result := True
    else Result := False;
  end;
end;


function UnpackXchars(var s: string; p: Boolean): Boolean;
var
  r: string;
  c: char;
  i, h, l, sl: Integer;

begin
  Result := False;
  sl := Length(s);
  i := 0;
  while i < sl do
  begin
    Inc(i);
    c := s[i];
    if c = '%' then
    begin
      if i > sl-2 then Exit;
      l := Pos(UpCase(s[i+2]), rrHiHexChar)-1;
      h := Pos(UpCase(s[i+1]), rrHiHexChar)-1;
      if (h = -1) or (l = -1) then Exit;
      r := r + Chr(h shl 4 or l);
      Inc(i, 2);
      Continue;
    end;
    if p then
    begin
      if not __pchar(c) and (c <> '/') then Exit;
    end else
    begin
      if not __uchar(c) then Exit
    end;
    r := r + c;
  end;
  s := r;
  Result := True;
end;

function UnpackUchars(var s: string): Boolean;
begin
  Result := UnpackXchars(s, False);
end;


function UnpackPchars(var s: string): Boolean;
begin
  Result := UnpackXchars(s, True);
end;

function ProcessQuotes(var s: string): Boolean;
var
  r: string;
  i: Integer;
  KVC: Boolean;
  c: Char;
begin
  Result := False;
  KVC := False;
  for i := 1 to Length(s) do
  begin
    c := s[i];
    case c of
      #0..#9, #11..#12, #14..#31 : Exit;
      '"' : begin KVC := not KVC; Continue end;
    end;
    if KVC then r := r + '%' + Hex2(Byte(c)) else r := r + c;
  end;
  Result := not KVC;
  if Result then s := r;
end;

function _Val(const S: string; var V: Integer): Boolean;
var
  I, R: Integer;
  C: Char;
begin
  Result := False;
  if S = '' then Exit;
  R := 0;
  for I := 1 to Length(S) do
  begin
    C := S[I];
    if not __digit(C) then Exit;
    R := (R * 10) + Ord(C) - Ord('0');
  end;
  Result := True;
  V := R;
end;


function StoI(const S: string): Integer;
begin
  if not _Val(S, Result) then Result := 0;
end;

function _LogOK(const Name: string; var Handle: Integer): Boolean;
begin
  if Handle = 0 then
  begin
    Handle := _CreateFile(Name, [cWrite]);
    if Handle <> INVALID_HANDLE_VALUE then if SetFilePointer(Handle, 0, nil, FILE_END) = -1 then ClearHandle(Handle);
  end;
  Result := Handle <> INVALID_HANDLE_VALUE;
end;

function InetAddr(const s: string): Integer;
begin
  Result := inet_addr(PChar(s))
end;

function AddrInet(i: Integer): string;
var
  r: record a, b, c, d: Byte end absolute i;
begin
  Result := ItoS(r.a)+'.'+ItoS(r.b)+'.'+ItoS(r.c)+'.'+ItoS(r.d);
end;


const
    shell32 = 'shell32.dll';


function FindExecutable; external shell32 name 'FindExecutableA';


procedure XAdd(var Critical, Normal: Integer); assembler;
asm
  mov  ecx, [edx]
  xadd [eax], ecx  // !!! i486+
  mov  [edx], ecx
end;

procedure GetBias;
var
  T, L: TFileTime;
begin
  GetSystemTimeAsFileTime(T);
  FileTimeToLocalFileTime(T, L);

  TimeZoneBias := uCvtGetFileTime(T.dwLowDateTime, T.dwHighDateTime) -
    uCvtGetFileTime(L.dwLowDateTime, L.dwHighDateTime);
end;


type
  THostCache = class
    Addr: Integer;
    Name: string;
  end;

  THostCacheColl = class(TSortedColl)
    function Compare(Key1, Key2: Pointer): Integer; override;
    function KeyOf(Item: Pointer): Pointer; override;
  end;

var
  HostCache: THostCacheColl;

function THostCacheColl.Compare(Key1, Key2: Pointer): Integer;
begin
  Result := Integer(Key1) - Integer(Key2);
end;

function THostCacheColl.KeyOf(Item: Pointer): Pointer;
begin
  Result := Pointer(THostCache(Item).Addr);
end;


function GetHostNameByAddr(Addr: Integer): string;
var
  p: PHostEnt;
  i: Integer;
  f: Boolean;
  c: THostCache;
  ok: Boolean;
  he: PHostEnt;
  HostName: string;
begin
  HostCache.Enter;
  f := HostCache.Search(Pointer(Addr), i);
  if f then Result := THostCache(HostCache[i]).Name;
  HostCache.Leave;
  if f then Exit;
  p := gethostbyaddr(@addr, 4, PF_INET);
  ok := False;
  if p <> nil then
  begin // host name got - now get address of this name
    HostName := p^.h_name;
    he := gethostbyname(PChar(HostName));
    if he <> nil then
    begin // address got - now compare it with the real one
      ok := PIntArray(he^.h_addr_list^)^[0] = Addr;
    end;
  end;
  if ok then Result := HostName else Result := AddrInet(Addr);
  HostCache.Enter;
  f := HostCache.Search(Pointer(Addr), i);
  if not f then
  begin
    c := THostCache.Create;
    c.Addr := Addr;
    c.Name := Result;
    HostCache.AtInsert(i, c);
  end;
  HostCache.Leave;
end;

function Vl(const s: string): Integer;
var
  a, i, l: Integer;
  c: Char;
begin
  Result := -1;
  l := Length(s);
  if L > 9 then Exit;
  a := 0;
  for i := 1 to l do
  begin
    C := s[i];
    if (C < '0') or (C > '9') then Exit;
    a := a * 10 + Ord(C) - Ord('0');
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

end.

