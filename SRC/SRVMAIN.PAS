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

unit SrvMain;

interface

procedure ComeOn;

implementation

uses
  {$IFDEF DEF_SSL}
  xSSL,
  SSLeay,
  {$ENDIF}
  WinSock,
  Windows,
  xBase;

const

  CIndexFile  = 'index.html';
  ScriptsPath = '/cgi-bin/';

  CHTTPServerThreadBufSize = $2000;
  MaxStatusCodeIdx = 36;
  StatusCodes : array[0..MaxStatusCodeIdx] of record Code: Integer; Msg: string end =
  ((Code:100; Msg:'Continue'),
   (Code:101; Msg:'Switching Protocols'),
   (Code:200; Msg:'OK'),
   (Code:201; Msg:'Created'),
   (Code:202; Msg:'Accepted'),
   (Code:203; Msg:'Non-Authoritative Information'),
   (Code:204; Msg:'No Content'),
   (Code:205; Msg:'Reset Content'),
   (Code:206; Msg:'Partial Content'),
   (Code:300; Msg:'Multiple Choices'),
   (Code:301; Msg:'Moved Permanently'),
   (Code:302; Msg:'Moved Temporarily'),
   (Code:303; Msg:'See Other'),
   (Code:304; Msg:'Not Modified'),
   (Code:305; Msg:'Use Proxy'),
   (Code:400; Msg:'Bad Request'),
   (Code:401; Msg:'Unauthorized'),
   (Code:402; Msg:'Payment Required'),
   (Code:403; Msg:'Forbidden'),
   (Code:404; Msg:'Not Found'),
   (Code:405; Msg:'Method Not Allowed'),
   (Code:406; Msg:'Not Acceptable'),
   (Code:407; Msg:'Proxy Authentication Required'),
   (Code:408; Msg:'Request Time-out'),
   (Code:409; Msg:'Conflict'),
   (Code:410; Msg:'Gone'),
   (Code:411; Msg:'Length Required'),
   (Code:412; Msg:'Precondition Failed'),
   (Code:413; Msg:'Request Entity Too Large'),
   (Code:414; Msg:'Request-URI Too Large'),
   (Code:415; Msg:'Unsupported Media Type'),
   (Code:500; Msg:'Internal Server Error'),
   (Code:501; Msg:'Not Implemented'),
   (Code:502; Msg:'Bad Gateway'),
   (Code:503; Msg:'Service Unavailable'),
   (Code:504; Msg:'Gateway Time-out'),
   (Code:505; Msg:'HTTP Version not supported'));

type
  TEntityHeader = class;
  TCollector = class;

  TAbstractHttpResponseData = class
  end;

  THttpResponseDataFileHandle = class(TAbstractHttpResponseData)
    FHandle: Integer;
    constructor Create(AHandle: Integer);
  end;

  THttpResponseDataEntity = class(TAbstractHttpResponseData)
    FEntityHeader : TEntityHeader;
    constructor Create(AEntityHeader : TEntityHeader);
  end;

  THttpResponseErrorCode = class(TAbstractHttpResponseData)
    FErrorCode: Integer;
    constructor Create(AErrorCode: Integer);
  end;

  PHTTPServerThreadBufer = ^THTTPServerThreadBufer;
  THTTPServerThreadBufer = array[0..CHTTPServerThreadBufSize-1] of Char;

  TPipeReadStdThread = class(TThread)
    Error: Boolean;
    HPipe: Integer;
    Buffer: PHTTPServerThreadBufer;
    EntityHeader: TEntityHeader;
    Collector: TCollector;
    procedure Execute; override;
  end;

  TPipeWriteStdThread = class(TThread)
    HPipe: Integer;
    s: string;
    procedure Execute; override;
  end;

  TPipeReadErrThread = class(TThread)
    HPipe: Integer;
    s: string;
    procedure Execute; override;
  end;

  TContentType = class
    ContentType,
    Extension: string;
  end;

  TContentTypeColl = class(TSortedColl)
    function Compare(Key1, Key2: Pointer): Integer; override;
    function KeyOf(Item: Pointer): Pointer; override;
  end;

  THTTPData = class;

  THTTPServerThread = class(TThread)
    RemoteHost,
    RemoteAddr: string;
    Buffer: THTTPServerThreadBufer;
    Socket: TSocket;
    constructor Create;
    procedure PrepareResponse(d: THTTPData);
    procedure Execute; override;
    destructor Destroy; override;
  end;

  TGeneralHeader = class
    CacheControl,            // Section 14.9
    Connection,              // Section 14.10
    Date,                    // Section 14.19
    Pragma,                  // Section 14.32
    TransferEncoding,        // Section 14.40
    Upgrade,                 // Section 14.41
    Via : string;            // Section 14.44
    function Filter(const z, s: string): Boolean;
    function OutString: string;
  end;


  TResponseHeader = class
    Age,                    // Section 14.6
    Location,               // Section 14.30
    ProxyAuthenticate,      // Section 14.33
    Public_,                // Section 14.35
    RetryAfter,             // Section 14.38
    Server,                 // Section 14.39
    Vary,                   // Section 14.43
    Warning,                // Section 14.45
    WWWAuthenticate         // Section 14.46
      : string;
    function OutString: string;
  end;

  TRequestHeader = class
    Accept,                  // Section 14.1
    AcceptCharset,           // Section 14.2
    AcceptEncoding,          // Section 14.3
    AcceptLanguage,          // Section 14.4
    Authorization,           // Section 14.8
    From,                    // Section 14.22
    Host,                    // Section 14.23
    IfModifiedSince,         // Section 14.24
    IfMatch,                 // Section 14.25
    IfNoneMatch,             // Section 14.26
    IfRange,                 // Section 14.27
    IfUnmodifiedSince,       // Section 14.28
    MaxForwards,             // Section 14.31
    ProxyAuthorization,      // Section 14.34
    Range,                   // Section 14.36
    Referer,                 // Section 14.37
    UserAgent: string;       // Section 14.42
    function Filter(const z, s: string): Boolean;
  end;

  TCollector = class
  private
    Parsed: Boolean;
    Lines: TStringColl;
    CollectStr: string;
    ContentLength: Integer;
  public
    EntityBody: string;
    GotEntityBody,
    CollectEntityBody: Boolean;
    function Collect(var Buf: THTTPServerThreadBufer; j: Integer): Boolean;
    constructor Create;
    destructor Destroy; override;
    function GetNextLine: string;
    function LineAvail: Boolean;
    procedure SetContentLength(i: Integer);
  end;


  TEntityHeader = class
    Allow,                   // Section 14.7
    ContentBase,             // Section 14.11
    ContentEncoding,         // Section 14.12
    ContentLanguage,         // Section 14.13
    ContentLength,           // Section 14.14
    ContentLocation,         // Section 14.15
    ContentMD5,              // Section 14.16
    ContentRange,            // Section 14.17
    ContentType,             // Section 14.18
    ETag,                    // Section 14.20
    Expires,                 // Section 14.21
    LastModified,            // Section 14.29
    EntityBody: string;
    EntityLength: Integer;
    CGIStatus,
    CGILocation: string;
    function Filter(const z, s: string): Boolean;
    procedure CopyEntityBody(Collector: TCollector);
    function OutString: string;
  end;

  THTTPData = class
    RequestCollector: TCollector;
    FileNfo: TFileINfo;

    FHandle,
    StatusCode,
    HTTPVersionHi,
    HTTPVersionLo: Integer;

    TransferFile,
    ReportError,
    KeepAlive: Boolean;

    ErrorMsg,
    Method, RequestURI, HTTPVersion,
    URIPath, URIParams, URIQuery, URIQueryParam : string;

    ResponceObjective: TAbstractHttpResponseData;

    RequestGeneralHeader: TGeneralHeader;
    RequestRequestHeader: TRequestHeader;
    RequestEntityHeader: TEntityHeader;

    ResponseGeneralHeader: TGeneralHeader;
    ResponseResponseHeader: TResponseHeader;
    ResponseEntityHeader: TEntityHeader;

    constructor Create;
    destructor Destroy; override;

  end;

var
    {$IFDEF DEBUG}
    DebugExit: Boolean;
    {$ENDIF}

  ContentTypes: TContentTypeColl;
  ParamStr1,
  FAccessLog,
  FAgentLog,
  FErrorLog,
  FRefererLog: string;
  CSAccessLog,
  CSAgentLog,
  CSErrorLog,
  CSRefererLog: TRTLCriticalSection;
  HAccessLog,
  HAgentLog,
  HErrorLog,
  HRefererLog: Integer;


function FileTimeToStr(AT: Integer): string;
const
  wkday: array[0..6] of string = ('Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat');
var
  D: TSystemTime;
  T: TFileTime;
begin
  uCvtSetFileTime(AT, T.dwLowDateTime, T.dwHighDateTime);
  if FileTimeToSystemTime(T, D) then
  Result :=
  wkday[D.wDayOfWeek] + ', ' +
  ItoSz(D.wDay, 2) + ' ' +
  MonthE(D.wMonth) + ' ' +
  ItoS(D.wYear) + ' ' +
  ItoSz(D.wHour, 2) + ':' +
  ItoSz(D.wMinute, 2) + ':' +
  ItoSz(D.wSecond, 2);
end;

constructor THTTPServerThread.Create;
begin
  inherited Create(True);
end;

destructor THTTPServerThread.Destroy;
begin
  FreeObject(Socket);
  inherited Destroy;
end;

function TGeneralHeader.Filter(const z, s: string): Boolean;
begin
  Result := True;
  if z = 'CACHE-CONTROL'       then CacheControl       := s else // Section 14.9
  if z = 'CONNECTION'          then Connection         := s else // Section 14.10
  if z = 'DATE'                then Date               := s else // Section 14.19
  if z = 'PRAGMA'              then Pragma             := s else // Section 14.32
  if z = 'TRANSFER-ENCODING'   then TransferEncoding   := s else // Section 14.40
  if z = 'UPGRADE'             then Upgrade            := s else // Section 14.41
  if z = 'VIA'                 then Via                := s else // Section 14.44
    Result := False;
end;

function TRequestHeader.Filter(const z, s: string): Boolean;
begin
  Result := True;
  if z = 'ACCEPT'              then Accept             := s else // Section 14.1
  if z = 'ACCEPT-CHARSET'      then AcceptCharset      := s else // Section 14.2
  if z = 'ACCEPT-ENCODING'     then AcceptEncoding     := s else // Section 14.3
  if z = 'ACCEPT-LANGUAGE'     then AcceptLanguage     := s else // Section 14.4
  if z = 'AUTHORIZATION'       then Authorization      := s else // Section 14.8
  if z = 'FROM'                then From               := s else // Section 14.22
  if z = 'HOST'                then Host               := s else // Section 14.23
  if z = 'IF-MODIFIED-SINCE'   then IfModifiedSince    := s else // Section 14.24
  if z = 'IF-MATCH'            then IfMatch            := s else // Section 14.25
  if z = 'IF-NONE-MATCH'       then IfNoneMatch        := s else // Section 14.26
  if z = 'IF-RANGE'            then IfRange            := s else // Section 14.27
  if z = 'IF-UNMODIFIED-SINCE' then IfUnmodifiedSince  := s else // Section 14.28
  if z = 'MAX-FORWARDS'        then MaxForwards        := s else // Section 14.31
  if z = 'PROXY-AUTHORIZATION' then ProxyAuthorization := s else // Section 14.34
  if z = 'RANGE'               then Range              := s else // Section 14.36
  if z = 'REFERER'             then Referer            := s else // Section 14.37
  if z = 'USER-AGENT'          then UserAgent          := s else // Section 14.42
    Result := False
end;

procedure Add(var s, z: string; const a: string);
begin
  if z <> '' then s := s + a + ': '+z+#13#10;
end;

function TResponseHeader.OutString: string;
var
  s: string;
begin
  s := '';
  Add(s, Age,               'Age');                // Section 14.6
  Add(s, Location,          'Location');           // Section 14.30
  Add(s, ProxyAuthenticate, 'Proxy-Authenticate'); // Section 14.33
  Add(s, Public_,           'Public');             // Section 14.35
  Add(s, RetryAfter,        'Retry-After');        // Section 14.38
  Add(s, Server,            'Server');             // Section 14.39
  Add(s, Vary,              'Vary');               // Section 14.43
  Add(s, Warning,           'Warning');            // Section 14.45
  Add(s, WWWAuthenticate,   'WWW-Authenticate');   // Section 14.46
  Result := s;
end;

function TEntityHeader.OutString: string;
var
  s: string;
begin
  s := '';
  Add(s, Allow,           'Allow');             // Section 14.7
  Add(s, ContentBase,     'Content-Base');      // Section 14.11
  Add(s, ContentEncoding, 'Content-Encoding');  // Section 14.12
  Add(s, ContentLanguage, 'Content-Language');  // Section 14.13
  Add(s, ContentLength,   'Content-Length');    // Section 14.14
  Add(s, ContentLocation, 'Content-Location');  // Section 14.15
  Add(s, ContentMD5,      'Content-MD5');       // Section 14.16
  Add(s, ContentRange,    'Content-Range');     // Section 14.17
  Add(s, ContentType,     'Content-Type');      // Section 14.18
  Add(s, ETag,            'ETag');              // Section 14.20
  Add(s, Expires,         'Expires');           // Section 14.21
  Add(s, LastModified,    'Last-Modified');     // Section 14.29
  Result := s;
end;

function TGeneralHeader.OutString: string;
var
  s: string;
begin
  s := '';
  Add(s, CacheControl,     'Cache-Control');     // Section 14.9
  Add(s, Connection,       'Connection');        // Section 14.10
  Add(s, Date,             'Date');              // Section 14.19
  Add(s, Pragma,           'Pragma');            // Section 14.32
  Add(s, TransferEncoding, 'Transfer-Encoding'); // Section 14.40
  Add(s, Upgrade,          'Upgrade');           // Section 14.41
  Add(s, Via,              'Via');               // Section 14.44
  Result := s;
end;

procedure TEntityHeader.CopyEntityBody(Collector: TCollector);
begin
  EntityLength := Collector.ContentLength;
  ContentLength := ItoS(Collector.ContentLength);
  EntityBody := Copy(Collector.EntityBody, 1, EntityLength);
end;

function TEntityHeader.Filter(const z, s: string): Boolean;
begin
  Result := True;
  if z = 'ALLOW'            then Allow           := s else // 14.7
  if z = 'CONTENT-BASE'     then ContentBase     := s else // 14.11
  if z = 'CONTENT-ENCODING' then ContentEncoding := s else // 14.12
  if z = 'CONTENT-LANGUAGE' then ContentLanguage := s else // 14.13
  if z = 'CONTENT-LENGTH'   then ContentLength   := s else // 14.14
  if z = 'CONTENT-LOCATION' then ContentLocation := s else // 14.15
  if z = 'CONTENT-MD5'      then ContentMD5      := s else // 14.16
  if z = 'CONTENT-RANGE'    then ContentRange    := s else // 14.17
  if z = 'CONTENT-TYPE'     then ContentType     := s else // 14.18
  if z = 'ETAG'             then ETag            := s else // 14.20
  if z = 'EXPIRES'          then Expires         := s else // 14.21
  if z = 'LAST-MODIFIED'    then LastModified    := s else // 14.29
  if z = 'STATUS'           then CGIStatus       := s else
  if z = 'LOCATION'         then CGILocation     := s else
    Result := False;
end;

constructor THTTPData.Create;
begin
  inherited Create;
  RequestCollector := TCollector.Create;
  RequestGeneralHeader := TGeneralHeader.Create;
  RequestRequestHeader := TRequestHeader.Create;
  RequestEntityHeader := TEntityHeader.Create;
end;

destructor THTTPData.Destroy;
begin
  FreeObject(RequestCollector);
  FreeObject(RequestGeneralHeader);
  FreeObject(RequestRequestHeader);
  FreeObject(RequestEntityHeader);
  FreeObject(ResponseGeneralHeader);
  FreeObject(ResponseResponseHeader);
  FreeObject(ResponseEntityHeader);
  ZeroHandle(FHandle);
  inherited Destroy;
end;

procedure TCollector.SetContentLength(i: Integer);
begin
  ContentLength := i;
  GotEntityBody := ContentLength <= Length(EntityBody);
end;

function TCollector.LineAvail: Boolean;
begin
  Result := Lines.Count > 0;
end;

function TCollector.GetNextLine: string;
begin
  Result := Lines[0]; Lines.AtFree(0);
end;

function TCollector.Collect(var Buf: THTTPServerThreadBufer; j: Integer): Boolean;
var
  i: Integer;
begin
  if not CollectEntityBody then
  for i := 0 to j-1 do
  begin
    CollectStr := CollectStr + Buf[i];
    if Copy(CollectStr, Length(CollectStr)-1, 2) = #13#10 then
    begin
      CollectStr := Copy(CollectStr, 1, Length(CollectStr)-2);
      if CollectStr = '' then
      begin
        CollectEntityBody := True;
        Dec(j, i+1);
        if j > 0 then Move(Buf[i+1], Buf[0], j);
        Break;
      end else
      begin
        Lines.Add(CollectStr);
        CollectStr := '';
      end;
    end;
  end;

  if CollectEntityBody then
  begin
    if (CollectEntityBody) and (j>0) then
    begin
      i := Length(EntityBody);
      SetLength(EntityBody, i+j);
      Move(Buf, EntityBody[i+1], j);
    end;
    GotEntityBody := ContentLength <= Length(EntityBody);
  end;
  Result := True;
end;

constructor TCollector.Create;
begin
  inherited Create;
  Lines := TStringColl.Create;
end;

destructor TCollector.Destroy;
begin
  FreeObject(Lines);
  inherited Destroy;
end;


procedure TPipeWriteStdThread.Execute;
var
  j: Integer;
begin
  WriteFile(HPipe, s[1], Length(s), j, nil);
end;

function DoCollect(Collector: TCollector; EntityHeader: TEntityHeader; j: Integer; Buffer: THTTPServerThreadBufer): Boolean;
var
  s,z: string;
begin
  Result := True;
  if not Collector.Collect(Buffer, j) then Result := False else
  if Collector.CollectEntityBody then
  if not Collector.Parsed then
  begin
    Collector.Parsed := True;
    while Collector.LineAvail do
    begin
      s := Collector.GetNextLine;
      if Length(s)<4 then begin Result := False; Break end else
      begin
        GetWrdStrictUC(s, z);
        Delete(z, Length(z), 1);
        if not EntityHeader.Filter(z, s) then
        begin
          // New Feature !!!
        end;
      end;
    end;
    Collector.SetContentLength(StoI(EntityHeader.ContentLength));
  end;
end;

procedure TPipeReadErrThread.Execute;
var
  ss: ShortString;
  j: Integer;
begin
  repeat
    if not ReadFile(HPipe, ss[1], 250, j, nil) then Break;
    ss[0] := Char(j);
    s := s + ss;
  until Terminated;
end;


procedure TPipeReadStdThread.Execute;
var
  j: Integer;
begin
  repeat
    if not ReadFile(HPipe, Buffer^, CHTTPServerThreadBufSize, j, nil) then Break;
    Error := not DoCollect(Collector, EntityHeader, j, Buffer^);
    if Error then Break;
    if (Collector.ContentLength > 0) and (Collector.GotEntityBody) then Break;
  until Terminated ;
  j := GetLastError
end;

function ExecuteScript(const AExecutable, APath, AScript, AQueryParam, AEnvStr, AStdInStr: string; Buffer: THTTPServerThreadBufer; SelfThr: TThread; var ErrorMsg: string): TEntityHeader;
var
  SI: TStartupInfo;
  PI: TProcessInformation;
  Security: TSecurityAttributes;
  j, si_r, si_w, so_r, so_w, se_r, se_w: Integer;
  b: Boolean;
  Collector: TCollector;
  EntityHeader: TEntityHeader;
  PipeReadStdThread: TPipeReadStdThread;
  PipeWriteStdThread: TPipeWriteStdThread;
  PipeReadErrThread: TPipeReadErrThread;
  s: string;
begin
  Result := nil;

  with Security do
  begin
    nLength := SizeOf(TSecurityAttributes);
    lpSecurityDescriptor := nil;
    bInheritHandle := True;
  end;

  CreatePipe(si_r, si_w, @Security, 0);
  CreatePipe(so_r, so_w, @Security, 0);
  CreatePipe(se_r, se_w, @Security, 0);

  FillChar(SI, SizeOf(SI), 0);
  SI.CB := SizeOf(SI);
  SI.dwFlags := STARTF_USESTDHANDLES;
  SI.hStdInput := si_r;
  SI.hStdOutput := so_w;
  SI.hStdError := se_w;
  if AExecutable = AScript then s := AExecutable else s := AExecutable + ' ' + AScript;
  if AQueryParam <> '' then s := s + ' ' + AQueryParam;

  b := CreateProcess(
    nil,                     // pointer to name of executable module
    PChar(DelSpaces(s)),  // pointer to command line string
    @Security,               // pointer to process security attributes
    @Security,               // pointer to thread security attributes
    True,                    // handle inheritance flag
    DETACHED_PROCESS or
    CREATE_SUSPENDED,        // creation flags
    PChar(AEnvStr),          // pointer to new environment block
    PChar(APath),            // pointer to current directory name
    SI,                      // pointer to STARTUPINFO
    PI                       // pointer to PROCESS_INFORMATION
  );

  if not b then
  begin
    ErrorMsg := SysErrorMsg(GetLastError);
    CloseHandles([si_r, si_w, so_r, so_w, se_r, se_w]);
    Exit;
  end;

  if AStdInStr = '' then
  begin
    PipeWriteStdThread := nil;
    CloseHandle(si_w);
  end else
  begin
    PipeWriteStdThread := TPipeWriteStdThread.Create(True);
    PipeWriteStdThread.s := AStdInStr;
    PipeWriteStdThread.HPipe := si_w;
    PipeWriteStdThread.Suspended := False;
  end;

  PipeReadErrThread := TPipeReadErrThread.Create(True);
  PipeReadErrThread.HPipe := se_r;
  PipeReadErrThread.Suspended := False;

  Collector := TCollector.Create;
  EntityHeader := TEntityHeader.Create;
  PipeReadStdThread := TPipeReadStdThread.Create(True);
  PipeReadStdThread.Priority := tpLower;
  PipeReadStdThread.Collector := Collector;
  PipeReadStdThread.EntityHeader := EntityHeader;
  PipeReadStdThread.Buffer := @Buffer;
  PipeReadStdThread.HPipe := so_r;
  PipeReadStdThread.Suspended := False;

  SelfThr.Priority := tpLowest;
  ResumeThread(PI.hThread);
  WaitForSingleObject(PI.hProcess, INFINITE);
  CloseHandle(PI.hThread);
  CloseHandle(PI.hProcess);

// Close StdIn
  CloseHandle(si_r);
  if PipeWriteStdThread <> nil then
  begin
    WaitForSingleObject(PipeWriteStdThread.Handle, INFINITE);
    PipeWriteStdThread.Terminate;
    FreeObject(PipeWriteStdThread);
    CloseHandle(si_w);
  end;

// Close StdErr

  CloseHandle(se_w);
  PipeReadErrThread.Terminate;
  WaitForSingleObject(PipeReadErrThread.Handle, INFINITE);
  ErrorMsg := PipeReadErrThread.s;
  FreeObject(PipeReadErrThread);
  CloseHandle(se_r);

// Close StdOut
  PipeReadStdThread.Terminate;
  CloseHandle(so_w);
  WaitForSingleObject(PipeReadStdThread.Handle, INFINITE);
  SelfThr.Priority := tpNormal;

  while not PipeReadStdThread.Error do
  begin
    if not ReadFile(so_r, Buffer, CHTTPServerThreadBufSize, j, nil) then Break;
    PipeReadStdThread.Error := not DoCollect(Collector, EntityHeader, j, Buffer);
    if (Collector.ContentLength > 0) and (Collector.GotEntityBody) then Break;
  end;
  CloseHandle(so_r);

  if PipeReadStdThread.Error or not Collector.GotEntityBody then FreeObject(Collector);
  FreeObject(PipeReadStdThread);
  if Collector = nil then FreeObject(EntityHeader) else
  begin
    if Collector.ContentLength = 0 then
    begin
      Collector.ContentLength := Length(Collector.EntityBody);
      EntityHeader.ContentLength := ItoS(Collector.ContentLength);
    end;
    EntityHeader.CopyEntityBody(Collector);
    FreeObject(Collector);
    Result := EntityHeader;
  end;
end;

procedure AddAgentLog(const AAgent: string);
var
  s: string;
  b: Integer;
begin
  s := AAgent + #13#10;
  EnterCriticalSection(CSAgentLog);
  WriteFile(HAgentLog, s[1], Length(s), b, nil);
  LeaveCriticalSection(CSAgentLog);
end;


procedure AddRefererLog(const ARefererSrc, ARefererDst: string);
var
  s: string;
  b: Integer;
begin
  if ARefererSrc = '' then Exit;
  s := ARefererSrc + ' -> ' + ARefererDst + #13#10;
  EnterCriticalSection(CSRefererLog);
  WriteFile(HRefererLog, s[1], Length(s), b, nil);
  LeaveCriticalSection(CSRefererLog);
end;

function CurTime: string;
var
  lt: TSystemTime;
  b: Integer;
  s: string;
begin
  GetLocalTime(lt);
  b := TimeZoneBias;
  if b < 0 then begin b := -b; s := s+'+' end else s := s + '-';
  b := b div 60;
  Result := '['+
        ItoSz(lt.wDay, 2) + '/' +
        MonthE(lt.wMonth) + '/' +
        ItoS(lt.wYear) + ':' +
        ItoSz(lt.wHour,2) + ':' +
        ItoSz(lt.wMinute,2) + ':' +
        ItoSz(lt.wSecond, 2) + ' ' +
        s +
        ItoSz(b div 60, 2) +
        ItoSz(b mod 60, 2) +
        ']';
end;

procedure AddAccessLog(const ARemoteHost, ARequestLine, AHTTPVersion: string; AStatusCode, ALength: Integer);
var
  z,k: string;
  b: Integer;
begin
  if ALength = -1 then z := '-' else z := ItoS(ALength);
  if AHTTPVersion = '' then k := '' else k := ' ' + AHTTPVersion;
  z := ARemoteHost + ' - - '+CurTime+' "' +
        ARequestLine + k +
        '" ' +
        ItoS(AStatusCode) + ' ' +
        z+
       #13#10;
  EnterCriticalSection(CSAccessLog);
  WriteFile(HAccessLog, z[1], Length(z), b, nil);
  LeaveCriticalSection(CSAccessLog);
end;

procedure AddErrorLog(const AErr: string);
var
  s: string;
  b: Integer;
begin
  s := CurTime + ' '+ AErr + #13#10;
  EnterCriticalSection(CSErrorLog);
  WriteFile(HErrorLog, s[1], Length(s), b, nil);
  LeaveCriticalSection(CSErrorLog);
end;

constructor THttpResponseDataEntity.Create(AEntityHeader : TEntityHeader);
begin
  inherited Create;
  FEntityHeader := AEntityHeader;
end;

constructor THttpResponseErrorCode.Create(AErrorCode: Integer);
begin
  inherited Create;
  FErrorCode := AErrorCode;
end;

constructor THttpResponseDataFileHandle.Create(AHandle: Integer);
begin
  FHandle := AHandle
end;

function OpenRequestedFile(const AFName: string; thr: THttpServerThread; d: THttpData): TAbstractHttpResponseData;
var
  I, FHandle: Integer;
  z: string;
begin
// Try to open Requested file
  FHandle := _CreateFile(AFName, [cRead, cSequentialScan]);
  if FHandle = INVALID_HANDLE_VALUE then
  begin
    AddErrorLog('access to '+AFName+' failed for '+thr.RemoteHost+', reason: '+SysErrorMsg(GetLastError));
    Result := THttpResponseErrorCode.Create(404);
    Exit;
  end;
  if not GetFileNfoByHandle(FHandle, d.FileNfo) then
  begin
    Result := THttpResponseErrorCode.Create(404);
    Exit;
  end;
  z := LowerCase(CopyLeft(ExtractFileExt(AFName),2));
  if z <> '' then
  begin
    if not ContentTypes.Search(@z, I) then z := '' else z := TContentType(ContentTypes.FList^[I]).ContentType;
  end;
  if z = '' then z := 'text/plain';
  d.ResponseEntityHeader := TEntityHeader.Create;
  d.ResponseEntityHeader.ContentType := z;
  d.ResponseEntityHeader.EntityLength := d.FileNfo.Size;
  d.ResponseEntityHeader.LastModified := FileTimeToStr(d.FileNfo.Time);
  d.ResponseGeneralHeader.Date := FileTimeToStr(uGetSystemTime);
  Result := THttpResponseDataFileHandle.Create(FHandle);
end;

function GetEnvStr(thr: THttpServerThread; d: THttpData): string;
var
  s: string;
  p: PByteArray;
  j: Integer;

  procedure Add(const Name, Value: string); begin s := s + Name+'='+Value+#0 end;

begin
  s := '';
  p := Pointer(GetEnvironmentStrings);
  j := 0; while (p^[j]<>0) or (p^[j]<>0) do Inc(j);
  Inc(j);
  SetLength(s, j);
  Move(p^, s[1], j);
  FreeEnvironmentStrings(Pointer(p));
  Add('REMOTE_HOST', thr.RemoteHost);
  Add('REMOTE_ADDR', thr.RemoteAddr);
  Add('GATEWAY_INTERFACE', 'CGI/1.1');
  Add('SCRIPT_NAME', d.URIPath);
  Add('REQUEST_METHOD', d.Method);
  Add('HTTP_ACCEPT', d.RequestRequestHeader.Accept);                     // Section 14.1
  Add('HTTP_ACCEPT_CHARSET', d.RequestRequestHeader.AcceptCharset);      // Section 14.2
  Add('HTTP_ACCEPT_ENCODING', d.RequestRequestHeader.AcceptEncoding);    // Section 14.3
  Add('HTTP_ACCEPT_LANGUAGE', d.RequestRequestHeader.AcceptLanguage);    // Section 14.4
  Add('HTTP_FROM', d.RequestRequestHeader.From);                         // Section 14.22
  Add('HTTP_HOST', d.RequestRequestHeader.Host);                         // Section 14.23
  Add('HTTP_REFERER', d.RequestRequestHeader.Referer);                   // Section 14.37
  Add('HTTP_USER_AGENT', d.RequestRequestHeader.UserAgent);              // Section 14.42
  Add('QUERY_STRING', d.URIQuery);
  Add('SERVER_SOFTWARE', CServerName);
  Add('SERVER_NAME', 'RIT Research Labs');
  Add('SERVER_PROTOCOL', 'HTTP/1.0');
  Add('SERVER_PORT', ItoS(thr.Socket.FPort));
  Add('CONTENT_TYPE', d.RequestEntityHeader.ContentType);
  Add('CONTENT_LENGTH', d.RequestEntityHeader.ContentLength);
  Result := s + #0;
end;

function ReturnNewLocation(const ALocation: string; d: THTTPData): TAbstractHttpResponseData;
begin
  d.ResponseResponseHeader.Location := ALocation;
  Result := THttpResponseErrorCode.Create(302);
end;

function IsURL(const s: string): Boolean;
begin
  Result := Pos('://', s) > 0;
end;

function WebServerHttpResponse(thr: THttpServerThread; d: THTTPData): TAbstractHttpResponseData;
var
  s, z,
  LocalFName: string;
  i: Integer;
  ResponseEntityHeader: TEntityHeader;

procedure Exec;
begin
  ResponseEntityHeader := ExecuteScript(s, z, LocalFName, d.URIQueryParam, GetEnvStr(thr, d), d.RequestEntityHeader.EntityBody, thr.Buffer, thr, d.ErrorMsg);
end;

begin
  ResponseEntityHeader := nil;
  s := d.URIPath;

  Replace('/', '\', s);
  if (s='') or (s[1]<>'\') then
  begin
    Result := THttpResponseErrorCode.Create(403);
    Exit;
  end;
  if (Pos('..', s)>0) or
     (Pos(':',s)>0) or
     (Pos('\\',s)>0) then
  begin
    Result := THttpResponseErrorCode.Create(403);
    Exit;
  end;

  if s[Length(s)]='\' then s := s + CIndexFile else
  if ExtractFileExt(s) = '' then
  begin
    Result := ReturnNewLocation(d.URIpath+'/', d);
    Exit;
  end;
  LocalFName := ParamStr1 + s;

// Analyze file extension
  if Copy(d.URIPath, 1, Length(ScriptsPath)) = ScriptsPath then
  begin
    SetLength(s, 1000);
    z := ExtractFilePath(LocalFName);
    i := FindExecutable(PChar(ExtractFileName(LocalFName)), PChar(z), @s[1]);
    if i > 32 then
    begin
      SetLength(s, NulSearch(s[1]));
      Exec;
    end else
    begin
      if i = 31 then
      begin
        s := LocalFName;
        Exec;
      end else
      begin
        d.ErrorMsg := SysErrorMsg(i);
        Result := THttpResponseErrorCode.Create(500);
        Exit;
      end;
    end;
    if ResponseEntityHeader = nil then
    begin
      d.ErrorMsg := 'CGI script '+d.URIPath+' returned nothing';
      Result := THttpResponseErrorCode.Create(500);
    end else
    begin
      if ResponseEntityHeader.CGILocation <> '' then
      begin
        if IsURL(ResponseEntityHeader.CGILocation) then
        begin
          Result := ReturnNewLocation(ResponseEntityHeader.CGILocation, d);
        end else
        begin
          Result := OpenRequestedFile(ResponseEntityHeader.CGILocation, thr, d);
        end;
      end else
      begin
        Result := THttpResponseDataEntity.Create(ResponseEntityHeader);
      end;
    end;
    Exit;
  end;

  Result := OpenRequestedFile(LocalFName, thr, d);

end;

function HttpResponse(thr: THttpServerThread; d: THTTPData): TAbstractHttpResponseData;
begin
  Result := WebServerHttpResponse(thr, d);
  Exit;
end;

procedure THTTPServerThread.PrepareResponse(d: THTTPData);
var
  r: TAbstractHttpResponseData;
  rf: THttpResponseDataFileHandle absolute r;
  re: THttpResponseDataEntity absolute r;
  rc: THttpResponseErrorCode absolute r;
begin
  r := HttpResponse(Self, d);
  if r = nil then GlobalFail;
  if r is THttpResponseDataFileHandle then
  begin
    d.FHandle := rf.FHandle;
    d.TransferFile := True;
    d.ReportError := False;
    d.StatusCode := 200;
  end else
  if r is THttpResponseDataEntity then
  begin
    d.ResponseEntityHeader := re.FEntityHeader;
    d.ReportError := False;
    d.StatusCode := 200;
  end else
  if r is THttpResponseErrorCode then
  begin
    d.StatusCode := rc.FErrorCode;
  end else GlobalFail;
  FreeObject(r);
end;

procedure THTTPServerThread.Execute;
var
  i, j: Integer;
  s,z: string;
  d: THTTPData;
  AbortConnection: Boolean;

begin

  if not Socket.Handshake then Exit;

  RemoteAddr := AddrInet(Socket.FAddr);
  RemoteHost := GetHostNameByAddr(Socket.FAddr);

  repeat
    AbortConnection := False;
    d := THTTPData.Create;
    d.StatusCode := 400;
    d.ReportError := True;
    d.ResponseGeneralHeader := TGeneralHeader.Create;
    d.ResponseResponseHeader := TResponseHeader.Create;
    s := '';
    with d do repeat

      j := Socket.Read(Buffer, CHTTPServerThreadBufSize);
      if (j <= 0) or (Socket.Status <> 0) then Break;

      if not RequestCollector.Collect(Buffer, j) then Break;
      if not RequestCollector.CollectEntityBody then Continue;

      if not RequestCollector.Parsed then
      begin
        if not RequestCollector.LineAvail then Break;
        RequestCollector.Parsed := True;

    // Parse the request
        s := RequestCollector.GetNextLine;

        if not ProcessQuotes(s) then Break;

        GetWrdStrictUC(s, Method);    if s = '' then Break;
        GetWrdStrict(s, RequestURI);  if s = '' then Break;
        GetWrdStrict(s, HTTPVersion); if s <> '' then Break;

    // Parse HTTP version
        s := HTTPVersion;
        GetWrd(s, z, '/'); if z <> 'HTTP' then Break;
        GetWrd(s, z, '.');
        if not DigitsOnly(s) or not DigitsOnly(z) then Break;
        if not _Val(z, HttpVersionHi) then Break;
        if not _Val(s, HttpVersionLo) then Break;

        s := '';
        z := '';

        while RequestCollector.LineAvail do
        begin
          s := RequestCollector.GetNextLine;
          if Length(s)<4 then Break;
          GetWrdStrictUC(s, z);
          Delete(z, Length(z), 1);
          if not RequestGeneralHeader.Filter(z, s) and
             not RequestRequestHeader.Filter(z, s) and
             not RequestEntityHeader.Filter(z, s) then
          begin
            // New Feature !!!
          end;

          s := '';
          z := '';
        end;

        if (s <> '') or (z <> '') then Break;
        RequestCollector.SetContentLength(StoI(RequestEntityHeader.ContentLength));
      end;


      if not RequestCollector.GotEntityBody then Continue;

      // process intity body
      RequestEntityHeader.CopyEntityBody(RequestCollector);

      FreeObject(RequestCollector);

      KeepAlive := UpperCase(RequestGeneralHeader.Connection) = 'KEEP-ALIVE';

      if (Method <> 'GET') and
         (Method <> 'POST') and
         (Method <> 'HEAD') then
      begin
        StatusCode := 403;
        Break;
      end else
      begin

    // Parse URI
        s := RequestURI;
        {$IFDEF DEBUG}
        if s = '/exit/now' then DebugExit := True;
        {$ENDIF}
        i := Pos('?', s);
        if i > 0 then
        begin
          URIQuery := CopyLeft(s, i+1);
          DeleteLeft(s, i);
          if Pos('=', URIQuery) = 0 then
          begin
            URIQueryParam := URIQuery;
            if not UnpackPchars(URIQueryParam) then Break;
          end;
        end;
        i := Pos(';', s);
        if i > 0 then
        begin
          URIParams := CopyLeft(s, i+1);
          DeleteLeft(s, i);
        end;
        if not UnpackPchars(s) then Break;
        URIPath := s;

        AddRefererLog(d.RequestRequestHeader.Referer, d.URIPath);
        AddAgentLog(d.RequestRequestHeader.UserAgent);

        PrepareResponse(d);

        Break;
      end;
    until False;

  // Send a response
    with d do
    begin
      if ResponseEntityHeader = nil then ResponseEntityHeader := TEntityHeader.Create;

      s := ResponseEntityHeader.CGIStatus;
      if s <> '' then
      begin
        ReportError := True;
      end else
      begin
 // Get Status Line
        for i := 0 to MaxStatusCodeIdx do if StatusCode = StatusCodes[i].Code then
        begin
          s := StatusCodes[i].Msg;
          Break;
        end;
        if s = '' then GlobalFail;
        if ErrorMsg = '' then ErrorMsg := s;
        s := ItoS(StatusCode)+ ' '+ s;
      end;
      if ReportError then
      begin
        KeepAlive := False;
        ResponseEntityHeader.ContentType := 'text/html';
        ResponseEntityHeader.EntityBody :=
          '<HTML>'+
          '<TITLE>'+s+'</TITLE>'+
          '<BODY><H1>'+ErrorMsg+'</H1></BODY>'+
          '</HTML>';
        ResponseEntityHeader.EntityLength := Length(ResponseEntityHeader.EntityBody);
      end;

      ResponseEntityHeader.ContentLength := ItoS(ResponseEntityHeader.EntityLength);

      if KeepAlive then ResponseGeneralHeader.Connection := 'Keep-Alive';

      ResponseResponseHeader.Server := CServerName;

      if ReportError then i := -1 else i := ResponseEntityHeader.EntityLength;
      AddAccessLog(RemoteHost, Method + ' ' + URIPath, HTTPVersion, StatusCode,  i);

      s := 'HTTP/1.0 '+ s + #13#10+
        ResponseGeneralHeader.OutString+
        ResponseResponseHeader.OutString+
        ResponseEntityHeader.OutString+
        #13#10;

      if TransferFile then
      begin
        Socket.WriteStr(s);
        i := 0;
        repeat
          ReadFile(FHandle, Buffer, CHTTPServerThreadBufSize, j, nil);
          Inc(i, j);
          if i > FileNfo.Size then Break;
          if j = 0 then Break;
          j := Socket.Write(Buffer, j);
        until (j < CHTTPServerThreadBufSize) or (Socket.Status <> 0);
        if i <> FileNfo.Size then AbortConnection := True;
        ZeroHandle(FHandle);
      end else
      begin
        s := s + ResponseEntityHeader.EntityBody + #13#10;
        Socket.WriteStr(s);
      end;
      AbortConnection := AbortConnection or not KeepAlive;
    end;
    FreeObject(d);
  until AbortConnection
end;


function TContentTypeColl.Compare(Key1, Key2: Pointer): Integer;
begin
  Compare := CompareStr(PString(Key1)^, PString(Key2)^);
end;

function TContentTypeColl.KeyOf(Item: Pointer): Pointer;
begin
  Result := @TContentType(Item).Extension;
end;

procedure GetContentTypes(const CBase, SubName: string; Swap: Boolean);
const
  ClassBufSize = 1000;
var
  Buf: array[0..ClassBufSize] of Char;
  r: TContentType;
  s, z, t : string;
  i,
  ec,
  Key,
  SubKey,
  BufSize,                       // size of string buffer
  cSubKeys,                      // number of subkeys
  cchMaxSubkey,                  // longest subkey name length
  cchMaxClass,                   // longest class string length
  cValues,                       // number of value entries
  cchMaxValueName,               // longest value name length
  cbMaxValueData,                // longest value data length
  cbSecurityDescriptor: Integer; // security descriptor length
  ftLastWriteTime: TFileTime;    // last write time
begin
  Key := OpenRegKeyEx(CBase, KEY_QUERY_VALUE or KEY_ENUMERATE_SUB_KEYS);
  BufSize := ClassBufSize;
  ec := RegQueryInfoKey(
    Key,                        // handle of key to query
    @Buf,
    @BufSize,
    nil,
    @cSubKeys,
    @cchMaxSubkey,
    @cchMaxClass,
    @cValues,
    @cchMaxValueName,
    @cbMaxValueData,
    @cbSecurityDescriptor,
    @ftLastWriteTime);
  if ec <> ERROR_SUCCESS then
  begin
    RegCloseKey(Key);
    Exit
  end;
  for i := 0 to cSubKeys-1 do
  begin
    BufSize := ClassBufSize;
    ec := RegEnumKeyEx(
      Key,
      i,
      Buf,
      BufSize,
      nil,
      nil, // address of buffer for class string
      nil, // address for size of class buffer
      @ftLastWriteTime);
    if ec <> ERROR_SUCCESS then Continue;
    SetString(s, Buf, BufSize);
    SubKey := OpenRegKey(CBase+'\'+s);
    if SubKey = -1 then Continue;
    z := ReadRegString(SubKey, SubName);
    RegCloseKey(SubKey);
    if Swap then
    begin
      t := s;
      s := z;
      z := t;
    end;
    z := LowerCase(CopyLeft(z,2));
    if (z = '') or (s = '') then Continue;
    if ContentTypes.Search(@z, ec) then Continue;
    r := TContentType.Create;
    r.ContentType := s;
    r.Extension := z;
    ContentTypes.AtInsert(ec, r);
  end;
  RegCloseKey(Key);
end;

type
  TAdrB = packed record
    A, B, C, D: Byte;
  end;


function _Adr2Int(const s: string): Integer;

var
  CPos: Integer;
  Error: Boolean;

function Get: Byte;
var
  C: Char;
  R: Integer;
  err: Boolean;
begin
  Result := 0;
  if Error then Exit;
  err := False;
  R := Ord(S[CPos])-48;
  Inc(CPos);
  C := S[CPos];
  if (C >= '0') and (C <= '9') then
  begin
    R := R * 10 + (Ord(C)-48); Inc(CPos);
    C := S[CPos];
    if (C >= '0') and (C <= '9') then begin R := R * 10 + (Ord(C)-48); Inc(CPos) end else err := C <> '.';
  end else err := C <> '.';
  if (R > 255) or (err) then
  begin
    Error := True;
    Exit;
  end;
  Inc(CPos);
  Result := R;
end;

var
  A: TAdrB;
begin
  Error := False;
  CPos := 1;
  A.A := Get;
  A.B := Get;
  A.C := Get;
  A.D := Get;
  if Error then Result := -1 else Result := PInteger(@A)^;
end;

function Adr2Int(const s: string): Integer;
begin
  Result := _Adr2Int(s+'.');
end;


var
  BindPort, BindAddr: Integer;

procedure GetHomeDir;
var
  s: string;
  i: Integer;
begin
  if ParamCount < 1 then
  begin
    MessageBox(0, 'Path to home directory is absent!'#13#10+
                  'See READ.ME for details.'#13#10#13#10+
                  CServerName+' service failed to start.',
                  CServerName, CMB_FAILED);
    Exit;
  end;
  ParamStr1 := ParamStr(1);
  if ParamStr1[Length(ParamStr1)] = '\' then Delete(ParamStr1, Length(ParamStr1), 1);
  s := ParamStr1+'\'+CIndexFile;
  if not FileExists(s) then
  begin
    s := 'Access to "'+s+'" failed'#13#10'Reason: "'+SysErrorMsg(GetLastError)+'"'#13#10#13#10+
    CServerName+' service failed to start';
    MessageBox(0, PChar(s), CServerName, CMB_FAILED);
    Exit;
  end;
  BindPort := {$IFDEF DEF_SSL} 443 {$ELSE} 80 {$ENDIF};
  BindAddr := _INADDR_ANY;
  if ParamCount > 1 then
  begin
    i := Vl(ParamStr(2));
    if i <> -1 then BindPort := i;
  end;
  if ParamCount > 2 then
  begin
    i := Adr2Int(ParamStr(3));
    if i <> -1 then BindAddr := i;
  end;
end;


procedure ReadContentTypes;
begin
  ContentTypes := TContentTypeColl.Create;
  GetContentTypes('SOFTWARE\Classes\MIME\Database\Content Type', 'Extension', False);
  GetContentTypes('SOFTWARE\Classes', 'Content Type', True);
end;

procedure InitLogs;
begin
  FAccessLog := 'access_log';
  FAgentLog := 'agent_log';
  FErrorLog := 'error_log';
  FRefererLog := 'referer_log';
  if not _LogOK(FAccessLog, HAccessLog) or
     not _LogOK(FAgentLog, HAgentLog) or
     not _LogOK(FErrorLog, HErrorLog) or
     not _LogOK(FRefererLog, HRefererLog) then GlobalFail;
  InitializeCriticalSection(CSAccessLog);
  InitializeCriticalSection(CSAgentLog);
  InitializeCriticalSection(CSErrorLog);
  InitializeCriticalSection(CSRefererLog);
end;


procedure InitReseterThread;
begin
  SocketsColl := TColl.Create;
  ResetterThread := TResetterThread.Create;
end;


procedure MainLoop;
var
  J, err, ServerSocketHandle: Integer;
  NewSocketHandle: Integer;
  NewSocket: TSocket;
  NewThread: THTTPServerThread;
  WData: TWSAData;
  Addr: TSockAddr;
  s: string;
begin
  err := WSAStartup(MakeWord(1,1), WData);
  if err <> 0 then
  begin
    s := 'Failed to initialize WinSocket,error #'+ItoS(err);
    MessageBox(0, PChar(s), CServerName, CMB_FAILED);
    Halt;
  end;
  ServerSocketHandle := socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if ServerSocketHandle = INVALID_SOCKET then
  begin
    s := 'Failed to create a socket, Error #'+ItoS(WSAGetLastError);
    MessageBox(0, PChar(s), CServerName, CMB_FAILED);
    Halt;
  end;

  Addr.sin_family := AF_INET;
  Addr.sin_port := htons(BindPort);
  Addr.sin_addr.s_addr := BindAddr;
  if bind(ServerSocketHandle, Addr, SizeOf(Addr)) = SOCKET_ERROR then
  begin
    S := 'Failed to bind the socket, error #'+ItoS(WSAGetLastError)+'.'#13#10#13#10+
         'Probable reason is that another daemon is already running on the same port ('+ItoS(BindPort)+').';
    MessageBox(0, PChar(S), CServerName, CMB_FAILED);
    Halt;
  end;


  {$IFDEF DEF_SSL}
  xSSLeayInit;
  {$ENDIF DEF_SSL}


  InitReseterThread;

  listen(ServerSocketHandle, 5);

  repeat
    J := SizeOf(Addr);
    NewSocketHandle := accept(ServerSocketHandle, @Addr, @J);
    if NewSocketHandle = INVALID_SOCKET then
    begin
      asm nop end;
      Exit;
    end;
    NewSocket := {$IFDEF DEF_SSL}TSSLSocket{$ELSE}TSocket{$ENDIF}.Create;
    NewSocket.Handle := NewSocketHandle;
    NewSocket.FAddr := Addr.sin_addr.s_addr;
    NewSocket.FPort := Addr.sin_port;
    if not NewSocket.Startup then FreeObject(NewSocket) else
    begin
      SocketsColl.Enter;
      if SocksCount = 0 then ResetterThread.Resume;
      Inc(SocksCount);
      SocketsColl.Leave;
      NewThread := THTTPServerThread.Create;
      NewThread.FreeOnTerminate := True;
      NewThread.Socket := NewSocket;
      NewSocket.RegisterSelf;
      NewThread.Resume;
    end;
  until {$IFDEF DEBUG}DebugExit{$ELSE}False{$ENDIF};
  {$IFDEF DEBUG}
  CloseSocket(ServerSocketHandle);
  {$ENDIF}
end;

procedure ComeOn;
var
 i: Integer;
begin
//--- Set Hight priority class
//  SetPriorityClass(GetCurrentProcess, HIGH_PRIORITY_CLASS);

//--- Get and validate a home directory
  GetHomeDir;

//--- Initialize xBase Module
  xBaseInit;

//--- Read content types from registry and associate with file extensions
  ReadContentTypes;

// --- Open log files and initialize semaphores
  InitLogs;

// --- Perform main loop
  MainLoop;

// Non-debug version never exits :-)

{$IFDEF DEBUG}
  ResetterThread.Terminate;
  SetEvent(ResetterThread.oSleep);
  SocketsColl.Enter;
  for i := 0 to SocketsColl.Count-1 do shutdown(TSocket(SocketsColl[i]).Handle, 2);
  SocketsColl.Leave;
  while SocketsColl.Count > 0 do Sleep(1000);
  ResetterThread.Resume;
  WaitForSingleObject(ResetterThread.Handle, INFINITE);
  FreeObject(ResetterThread);
  FreeObject(SocketsColl);
  FreeObject(ContentTypes);
  xBaseDone;
  CloseHandle(HAccessLog);
  CloseHandle(HAgentLog);
  CloseHandle(HErrorLog);
  CloseHandle(HRefererLog);
  DeleteCriticalSection(CSAccessLog);
  DeleteCriticalSection(CSAgentLog);
  DeleteCriticalSection(CSErrorLog);
  DeleteCriticalSection(CSRefererLog);
  {$ENDIF}
end;

end.


