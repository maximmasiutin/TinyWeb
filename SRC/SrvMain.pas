//////////////////////////////////////////////////////////////////////////
//
//  TinyWeb 
//  Copyright (C) 1997-2000 RIT Research Labs
//  Copyright (C) 2000-2017 RITLABS S.R.L.
//  Copyright (C) 2021 Maxim Masiutin
//
//  This programs is free for commercial and non-commercial use as long as
//  the following conditions are aheared to.
//
//  Copyright remains RITLABS S.R.L., and as such any Copyright notices
//  in the code are not to be removed. If this package is used in a
//  product, RITLABS S.R.L. should be given attribution as the owner
//  of the parts of the library used. This can be in the form of a textual
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
//     "Based on TinyWeb Server by RITLABS S.R.L.."
//
//  THIS SOFTWARE IS PROVIDED BY RITLABS S.R.L. "AS IS" AND ANY EXPRESS
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
  {$IFDEF ODBC}
  OdbcAuth,
  {$ENDIF}
  WinSock,
  Windows,
  Messages,
  xBase;

const

  ScriptsPath = 'cgi-bin';

  CHTTPServerThreadBufSize = $2000;
  MaxStatusCodeIdx = 36;
  StatusCodes : array[0..MaxStatusCodeIdx] of record Code: Integer; Msg: AnsiString end =
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
    FHandle: THandle;
    constructor Create(AHandle: THandle);
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
  THTTPServerThreadBufer = array[0..CHTTPServerThreadBufSize-1] of AnsiChar;

  TPipeReadStdThread = class(TThread)
    Error: Boolean;
    HPipe: DWORD;
    Buffer: PHTTPServerThreadBufer;
    EntityHeader: TEntityHeader;
    Collector: TCollector;
    procedure Execute; override;
  end;

  TPipeWriteStdThread = class(TThread)
    HPipe: DWORD;
    s: AnsiString;
    procedure Execute; override;
  end;

  TPipeReadErrThread = class(TThread)
    HPipe: DWORD;
    s: AnsiString;
    procedure Execute; override;
  end;

  TContentType = class
    ContentType,
    Extension: AnsiString;
  end;

  TContentTypeColl = class(TSortedColl)
    function Compare(Key1, Key2: Pointer): Integer; override;
    function KeyOf(Item: Pointer): Pointer; override;
  end;

  THTTPData = class;

  THTTPServerThread = class(TThread)
    RemoteHost,
    RemoteAddr: AnsiString;
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
    Via : AnsiString;            // Section 14.44
    function Filter(const z, s: AnsiString): Boolean;
    function OutString: AnsiString;
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
      : AnsiString;
    IsNormalAuthenticateAfterEmptyUsernamePassword: Boolean;
    function OutString: AnsiString;
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
    UserAgent,               // Section 14.42
    Cookie: AnsiString;          // rfc-2109
    function Filter(const z, s: AnsiString): Boolean;
  end;

  TCollector = class
  private
    Parsed: Boolean;
    Lines: TStringColl;
    CollectStr: AnsiString;
    CollectLen: Integer;
    ContentLength: Integer;
  public
    EntityBody: AnsiString;
    GotEntityBody,
    CollectEntityBody: Boolean;
    function Collect(var Buf: THTTPServerThreadBufer; j: Integer): Boolean;
    constructor Create;
    destructor Destroy; override;
    function GetNextLine: AnsiString;
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
    {This is two headers for file download by CGI}
    AcceptRanges,            // Section 14.5
    ContentDisposition,      // Section 15.10
    EntityBody: AnsiString;
    EntityLength: Integer;
    SetCookie,
    CGIStatus,
    CGILocation: AnsiString;
    function Filter(const z, s: AnsiString): Boolean;
    procedure CopyEntityBody(Collector: TCollector);
    function OutString: AnsiString;
  end;

  THTTPData = class
    RequestCollector: TCollector;
    FileNfo: TFileINfo;

    FHandle: THandle;
    StatusCode,
    HTTPVersionHi,
    HTTPVersionLo: Integer;

    TransferFile,
    ReportError,
    KeepAliveInRequest,
    KeepAliveInReply: Boolean;

    ErrorMsg,
    Method, RequestURI, HTTPVersion, AuthUser, AuthPassword, AuthType,
    URIPath, URIParams, URIQuery, URIQueryParam : AnsiString;

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
  ContentTypes: TContentTypeColl;
  ParamStr1: AnsiString;

{$IFDEF LOGGING}
  FAccessLog,
  FAgentLog,
  FErrorLog,
  FRefererLog: AnsiString;
  CSAccessLog,
  CSAgentLog,
  CSErrorLog,
  CSRefererLog: TRTLCriticalSection;
  HAccessLog,
  HAgentLog,
  HErrorLog,
  HRefererLog: Thandle;
{$ENDIF}

function FileTimeToStr(AT: DWORD): AnsiString;
const
  wkday: array[0..6] of AnsiString = ('Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat');
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
  ItoSz(D.wSecond, 2) + ' GMT';
end;

function StrToFileTime(AStr: AnsiString): DWORD;
const
  CPatterns: AnsiString = #1'JAN'#1'FEB'#1'MAR'#1'APR'#1'MAY'#1'JUN'#1'JUL'#1'AUG'#1'SEP'#1'OCT'#1'NOV'#1'DEC'#1;
var
  D: TSystemTime;
  T: TFileTime;
  s, z, LSubstring: AnsiString;
  v: DWORD;
begin
  Result := INVALID_FILE_TIME;
  Clear(D, SizeOf(D));
  s := AStr;
  GetWrd(s, z, ' ');
  GetWrdD(s, z); v := Vl(z); if v = INVALID_VALUE then Exit; D.wDay := v;
  LSubstring := #1+UpperCase(z)+#1;
  GetWrdA(s, z); D.wMonth := Pos(LSubstring, CPatterns);
  if D.wMonth = 0 then Exit;
  D.wMonth := (D.wMonth+3) div 4;
  GetWrdD(s, z); v := Vl(z); if v = INVALID_VALUE then Exit; D.wYear := v;
  if D.wYear < 200 then
  begin
    if D.wYear < 50 then Inc(D.wYear, 2000) else Inc(D.wYear, 1900);
  end;
  GetWrdD(s, z); v := Vl(z); if v = INVALID_VALUE then Exit; D.wHour := v;
  GetWrdD(s, z); v := Vl(z); if v = INVALID_VALUE then Exit; D.wMinute := v;
  GetWrdD(s, z); v := Vl(z); if v = INVALID_VALUE then Exit; D.wSecond := v;
  if not SystemTimeToFileTime(D, T) then Exit;
  Result := uCvtGetFileTime(T.dwLowDateTime, T.dwHighDateTime);
end;

// 'Sunday, 17-May-98 18:44:23 GMT; length=4956'

constructor THTTPServerThread.Create;
begin
  inherited Create(True);
end;

destructor THTTPServerThread.Destroy;
begin
  FreeObject(Socket);
  inherited Destroy;
end;

function TGeneralHeader.Filter(const z, s: AnsiString): Boolean;
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

function TRequestHeader.Filter(const z, s: AnsiString): Boolean;
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
  if z = 'COOKIE'              then Cookie             := s else
    Result := False
end;

procedure Add(var s, z: AnsiString; const a: AnsiString);
begin
  if z <> '' then s := s + a + ': '+z+#13#10;
end;

function TResponseHeader.OutString: AnsiString;
var
  s: AnsiString;
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

function TEntityHeader.OutString: AnsiString;
var
  s: AnsiString;
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
  {This is two headers for file download by CGI}
  Add(s, AcceptRanges,    'Accept-Ranges');    // Section 14.5
  Add(s, ContentDisposition, 'Content-Disposition'); // Section 15.10
  Add(s, SetCookie,       'Set-Cookie');
  Result := s;
end;

function TGeneralHeader.OutString: AnsiString;
var
  s: AnsiString;
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

function TEntityHeader.Filter(const z, s: AnsiString): Boolean;
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
  {This is two headers for file download by CGI}
  if z = 'ACCEPT-RANGES'    then AcceptRanges    := s else // 14.5
  if z = 'CONTENT-DISPOSITION' then ContentDisposition := s else // 15.10
  if z = 'STATUS'           then
  CGIStatus       := s
  else
  if z = 'LOCATION'         then CGILocation     := s else
  if z = 'SET-COOKIE'       then SetCookie       := s else
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

function TCollector.GetNextLine: AnsiString;
begin
  Result := Lines[0]; Lines.AtFree(0);
end;

function TCollector.Collect(var Buf: THTTPServerThreadBufer; j: Integer): Boolean;
var
  i,l: Integer;
begin
  if not CollectEntityBody then
  begin
    l := Length(CollectStr);
    for i := 0 to j-1 do
    begin
      if l <= CollectLen then
      begin
        Inc(l, j + 100);
        SetLength(CollectStr, l);
      end;
      Inc(CollectLen);
      CollectStr[CollectLen] := Buf[i];
      if (CollectLen >= 2) and (CollectStr[CollectLen] = #10) and (CollectStr[CollectLen-1] = #13) then
      begin
        if CollectLen = 2 then
        begin
          CollectEntityBody := True;
          j := j - (i+1);
          if j > 0 then Move(Buf[i+1], Buf[0], j);
          Break;
        end else
        begin
          Lines.Add(Copy(CollectStr, 1, CollectLen-2));
          CollectLen := 0;
        end;
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
//  Lines.LongString;
end;

destructor TCollector.Destroy;
begin
  FreeObject(Lines);
  inherited Destroy;
end;


procedure TPipeWriteStdThread.Execute;
var
  j: DWORD;
  slen: Integer;
begin
  slen := Length(s);
  if slen > 0 then WriteFile(HPipe, s[1], slen, j, nil);
end;

function DoCollect(Collector: TCollector; EntityHeader: TEntityHeader; j: Integer; var Buffer: THTTPServerThreadBufer): Boolean;
var
  s,z: AnsiString;
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
  j: DWORD;
begin
  repeat
    if (not ReadFile(HPipe, ss[1], 250, j, nil)) or (j=0) then Break;
    ss[0] := AnsiChar(j);
    s := s + ss;
  until False;
end;


procedure TPipeReadStdThread.Execute;
var
  j: DWORD;
begin
  repeat
    if (not ReadFile(HPipe, Buffer^, CHTTPServerThreadBufSize, j, nil)) or (j = 0) then Break;
    Error := not DoCollect(Collector, EntityHeader, j, Buffer^);
    if Error then Break;
    if (Collector.ContentLength > 0) and (Collector.GotEntityBody) then Break;
  until False;
end;

function ExecuteScript(const AExecutable, APath, AScript, AQueryParam, AEnvStr, AStdInStr: AnsiString; Buffer: THTTPServerThreadBufer; SelfThr: TThread; var ErrorMsg: AnsiString): TEntityHeader;
var
  SI: TStartupInfoA;
  PI: TProcessInformation;
  Security: TSecurityAttributes;
  Actually: DWORD;
  si_r, si_w, so_r, so_w, se_r, se_w: THandle;
  b: Boolean;
  Collector: TCollector;
  EntityHeader: TEntityHeader;
  PipeReadStdThread: TPipeReadStdThread;
  PipeWriteStdThread: TPipeWriteStdThread;
  PipeReadErrThread: TPipeReadErrThread;
  s: AnsiString;

function ReportGUI: AnsiString;
var
  d, n, e: AnsiString;
begin
  FSPlit(AExecutable, d, n, e);
  Result := n+e+' is a GUI application';
end;

begin
  Result := nil;

  FillChar(Security, SizeOf(Security), 0);
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
  SI.dwFlags := STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW;
  SI.hStdInput := si_r;
  SI.hStdOutput := so_w;
  SI.hStdError := se_w;
  SI.wShowWindow := SW_HIDE;
  if AExecutable = AScript then s := AExecutable else s := AExecutable + ' ' + AScript;
  if AQueryParam <> '' then s := s + ' ' + AQueryParam;
  s := DelSpaces(s);
  if (s = '') or (AEnvStr = '') or (APath = '') then
  begin
    b := False;
  end else
  begin
    b := CreateProcessA(
      nil,                     // pointer to name of executable module
      @(s[1]),                 // pointer to command line AnsiString
      @Security,               // pointer to process security attributes
      @Security,               // pointer to thread security attributes
      True,                    // handle inheritance flag
      CREATE_SUSPENDED,        // creation flags
      @(AEnvStr[1]),           // pointer to new environment block
      @(APath[1]),             // pointer to current directory name
      SI,                      // pointer to STARTUPINFO
      PI                       // pointer to PROCESS_INFORMATION
    );
  end;

  if b then
  begin
    {--$IFDEF CHECK_GUI}
    if WaitForInputIdle(PI.hProcess, 0) = WAIT_TIMEOUT then
    begin
      ErrorMsg := ReportGUI;
      TerminateProcess(PI.hProcess, 0);
      CloseHandle(PI.hThread);
      CloseHandle(PI.hProcess);
      b := False;
    end;
    {--$ENDIF}
  end else
  begin
    ErrorMsg := SysErrorMsg(GetLastError);
  end;

  if not b then
  begin
    CloseHandles([si_r, si_w, so_r, so_w, se_r, se_w]);
    Exit;
  end;

  if AStdInStr = '' then
  begin
    PipeWriteStdThread := nil;
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

// Close StdIn
  CloseHandle(si_r);
  if PipeWriteStdThread = nil then
  begin
    CloseHandle(si_w);
  end else
  begin
    WaitForSingleObject(PipeWriteStdThread.Handle, INFINITE);
    PipeWriteStdThread.Terminate;
    FreeObject(PipeWriteStdThread);
    CloseHandle(si_w);
  end;

// Close StdErr

  CloseHandle(se_w);
  WaitForSingleObject(PipeReadErrThread.Handle, INFINITE);
  PipeReadErrThread.Terminate;
  ErrorMsg := PipeReadErrThread.s;
  FreeObject(PipeReadErrThread);
  CloseHandle(se_r);

// Close StdOut
  CloseHandle(so_w);
  WaitForSingleObject(PipeReadStdThread.Handle, INFINITE);
  PipeReadStdThread.Terminate;
  SelfThr.Priority := tpNormal;

  while not PipeReadStdThread.Error do
  begin
    if (not ReadFile(so_r, Buffer, CHTTPServerThreadBufSize, Actually, nil)) or (Actually = 0) then Break;
    PipeReadStdThread.Error := not DoCollect(Collector, EntityHeader, Actually, Buffer);
    if (Collector.ContentLength > 0) and (Collector.GotEntityBody) then Break;
  end;
  CloseHandle(so_r);
  CloseHandle(PI.hProcess);

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

{$IFDEF LOGGING}

procedure AddAgentLog(const AAgent: AnsiString);
var
  s: AnsiString;
  b: DWORD;
  slen: Integer;
begin
  s := AAgent + #13#10;
  EnterCriticalSection(CSAgentLog);
  slen := Length(s);
  WriteFile(HAgentLog, s[1], slen, b, nil);
  LeaveCriticalSection(CSAgentLog);
end;


procedure AddRefererLog(const ARefererSrc, ARefererDst: AnsiString);
var
  s: AnsiString;
  b: DWORD;
  slen: Integer;
begin
  if ARefererSrc = '' then Exit;
  s := ARefererSrc + ' -> ' + ARefererDst + #13#10;
  EnterCriticalSection(CSRefererLog);
  slen := Length(s);
  WriteFile(HRefererLog, s[1], slen, b, nil);
  LeaveCriticalSection(CSRefererLog);
end;

function CurTime: AnsiString;
var
  lt: TSystemTime;
  b: Integer;
  s: AnsiString;
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

procedure AddAccessLog(const ARemoteHost, ARequestLine, AHTTPVersion, AUserName: AnsiString; AStatusCode, ALength: Integer);
var
  authuser,z,k: AnsiString;
  b: DWORD;
  slen: Integer;
begin
  if ALength = -1 then z := '-' else z := ItoS(ALength);
  if AHTTPVersion = '' then k := '' else k := ' ' + AHTTPVersion;
  if AUserName = '' then authuser := '-' else authuser := AUserName;
  z := ARemoteHost +  // Remote hostname (or IP number if DNS hostname is not available)
       ' - ' +        // rfc-931
       authuser+' '+  // The username as which the user has authenticated himself
       CurTime+' '+   // Date and time of the request
       '"' + ARequestLine + k + '" ' +  // The request line exactly as it came from the client
       ItoS(AStatusCode) + ' ' + // The HTTP status code returned to the client
       z+             // The content-length of the document transferred
       #13#10;
  EnterCriticalSection(CSAccessLog);
  slen := Length(z);
  WriteFile(HAccessLog, z[1], slen, b, nil);
  LeaveCriticalSection(CSAccessLog);
end;

procedure AddErrorLog(const AErr: AnsiString);
var
  s: AnsiString;
  b: DWORD;
  slen: Integer;
begin
  s := CurTime + ' '+ AErr + #13#10;
  EnterCriticalSection(CSErrorLog);
  slen := Length(s);
  WriteFile(HErrorLog, s[1], slen, b, nil);
  LeaveCriticalSection(CSErrorLog);
end;
{$ENDIF}

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

constructor THttpResponseDataFileHandle.Create(AHandle: THandle);
begin
  FHandle := AHandle
end;


function OpenRequestedFile(const AFName: AnsiString; thr: THttpServerThread; d: THttpData): TAbstractHttpResponseData;
var
  I: Integer;
  FHandle: THandle;
  z: AnsiString;
  fa: DWORD;
begin
  if AFName = '' then
  begin
    Result := nil;
    Exit;
  end;
// Try to open Requested file
  z := LowerCase(AFName);
  if Copy(z, 1, Length(ParamStr1)) <> LowerCase(ParamStr1) then
  begin
    Result := THttpResponseErrorCode.Create(403);
    Exit;
  end;
  if Copy(z, 1, Length(ParamStr1)+1+Length(ScriptsPath)+1) = ParamStr1+'\'+(ScriptsPath)+'\' then
  begin
    Result := THttpResponseErrorCode.Create(403);
    Exit;
  end;
  fa := GetFileAttributesA(@(AFName[1]));
  if ((fa and FILE_ATTRIBUTE_DIRECTORY) <> 0) or
       ((fa and FILE_ATTRIBUTE_HIDDEN) <> 0) or
       ((fa and FILE_ATTRIBUTE_SYSTEM) <> 0) then
  begin
    Result := THttpResponseErrorCode.Create(403);
    Exit;
  end;
  FHandle := _CreateFile(AFName, [cRead, cSequentialScan]);
  if FHandle = INVALID_HANDLE_VALUE then
  begin
{$IFDEF LOGGING}
    AddErrorLog('access to '+AFName+' failed for '+thr.RemoteHost+', reason: '+SysErrorMsg(GetLastError));
{$ENDIF}
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

function GetEnvStr(thr: THttpServerThread; d: THttpData; const PathInfo: AnsiString): AnsiString;
var
  s: AnsiString;
  AuxS: AnsiString;
  p: PAnsiChar;
  j: Integer;

  procedure Add(const Name, Value: AnsiString); begin s := s + Name+'='+Value+#0 end;

begin
  s := '';
  p := GetEnvironmentStringsA;
  j := 0; while (p[j]<>#0) or (p[j+1]<>#0) do Inc(j);
  Inc(j);
  SetLength(s, j);
  Move(p^, s[1], j);
  FreeEnvironmentStringsA(p);
  AuxS := PathInfo;
  Replace('\', '/', AuxS);
  if AuxS <> '' then AuxS := '/' + AuxS;
  Add('PATH_INFO', AuxS);
  if AuxS <> '' then AuxS := ParamStr1+'\'+PathInfo;
  Add('PATH_TRANSLATED', AuxS);
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
  Add('HTTP_COOKIE', d.RequestRequestHeader.Cookie);
  Add('QUERY_STRING', d.URIQuery);
  Add('SERVER_SOFTWARE', CServerName);
  Add('SERVER_NAME', 'RITLABS S.R.L.');
  Add('SERVER_PROTOCOL', d.HTTPVersion);
  Add('SERVER_PORT', ItoS(thr.Socket.FPort));
  Add('CONTENT_TYPE', d.RequestEntityHeader.ContentType);
  Add('CONTENT_LENGTH', d.RequestEntityHeader.ContentLength);
  Add('USER_NAME', d.AuthUser);
  Add('USER_PASSWORD', d.AuthPassword);
  Add('AUTH_TYPE', d.AuthType);
  Result := s + #0;
end;

function ReturnNewLocation(const ALocation: AnsiString; d: THTTPData): TAbstractHttpResponseData;
begin
  d.ResponseResponseHeader.Location := ALocation;
  Result := THttpResponseErrorCode.Create(302);
end;

function IsURL(const s: AnsiString): Boolean;
const
  Pattern: AnsiString = '://';
begin
  Result := Pos(Pattern, s) > 0;
end;

type
  TExecutableCache = class
    LocalFName, sResult: AnsiString;
    ReturnValue: HInst;
  end;

  TExecutableCacheColl = class(TSortedColl)
    function Compare(Key1, Key2: Pointer): Integer; override;
    function KeyOf(Item: Pointer): Pointer; override;
  end;

var
  ExecutableCache: TExecutableCacheColl;

function TExecutableCacheColl.Compare(Key1, Key2: Pointer): Integer;
begin
  Compare := CompareStr(PAnsiString(Key1)^, PAnsiString(Key2)^);
end;

function TExecutableCacheColl.KeyOf(Item: Pointer): Pointer;
begin
  Result := @TExecutableCache(Item).LocalFName;
end;

function FindExecutableCached(const LocalFName, sPath: AnsiString; var s: AnsiString): HInst;
var
  i: Integer;
  c: TExecutableCache;
  p: Pointer;
begin
  if (LocalFName = '') or (sPath = '') then
  begin
    Result := 0;
    Exit;
  end;
  ExecutableCache.Enter;
  if ExecutableCache.Search(@LocalFName, i) then
  begin
    p := ExecutableCache[i];
    c := TExecutableCache(p);
    s := StrAsg(c.sResult);
    Result := c.ReturnValue;
  end else
  begin
    SetLength(s, 1000);
    Result := FindExecutable(@(LocalFName[1]), @(sPath[1]), @s[1]);
    c := TExecutableCache.Create;
    c.ReturnValue := Result;
    c.LocalFName := StrAsg(LocalFName);
    if Result > 32 then
    begin
      SetLength(s, NulSearch(s[1]));
      c.sResult := StrAsg(s);
    end;
    ExecutableCache.AtInsert(i, c);
  end;
  ExecutableCache.Leave;
end;

type
  TRootCache = class
    FURI, FResult: AnsiString;
    IsCGI: Boolean;
  end;

  TRootCacheColl = class(TSortedColl)
    function Compare(Key1, Key2: Pointer): Integer; override;
    function KeyOf(Item: Pointer): Pointer; override;
  end;

var
  RootCacheColl: TRootCacheColl;


function TRootCacheColl.Compare(Key1, Key2: Pointer): Integer;
begin
  Compare := CompareStr(PAnsiString(Key1)^, PAnsiString(Key2)^);
end;

function TRootCacheColl.KeyOf(Item: Pointer): Pointer;
begin
  Result := @TRootCache(Item).FURI;
end;


function FindRootFileEx(const AURI: AnsiString; var IsCGI: Boolean): AnsiString;
var
  s, z: AnsiString;
begin
  IsCGI := False;
  Result := ParamStr1 + AURI + 'index.html';
  if FileExists(Result) then Exit;
  Result := ParamStr1 + AURI + 'index.htm';
  if FileExists(Result) then Exit;
  Result := ParamStr1 + AURI + 'index.html';
  s := GetEnvVariable('PATHEXT');
  while s <> '' do
  begin
    GetWrd(s, z, ';');
    if Length(z) < 2 then Continue;
    if z[1] <> '.' then Continue;
    z := ParamStr1+'\'+ScriptsPath+AURI+'index'+z;
    if FileExists(z) then begin Result := z; IsCGI := True; Exit end;
  end;
end;

function FindRootFile(const AURI: AnsiString; var IsCGI: Boolean): AnsiString;
var
  Found: Boolean;
  I: Integer;
  c: TRootCache;
  p: Pointer;
begin
  RootCacheColl.Enter;
  Found := RootCacheColl.Search(@AURI, I);
  if Found then
  begin
    p := RootCacheColl[i];
    c := TRootCache(p);
    IsCGI := c.IsCGI;
    Result := StrAsg(c.FResult);
  end;
  RootCacheColl.Leave;
  if Found then Exit;
  Result := FindRootFileEx(AURI, IsCGI);
  RootCacheColl.Enter;
  if not RootCacheColl.Search(@AURI, I) then
  begin
    c := TRootCache.Create;
    c.FURI := StrAsg(AURI);
    c.FResult := StrAsg(Result);
    c.IsCGI := IsCGI;
    RootCacheColl.AtInsert(I, c);
  end;
  RootCacheColl.Leave;

end;



function FileIsRegular(const FN: AnsiString): Boolean;
const
  CDot: AnsiChar = '.';
  fDevices: AnsiString =
    #1'CON'#1'LPT'#1'PRN'#1'NUL'#1'CLOCK$'#1'AUX'#1'COM1'#1'LPT1'#1'LPT2'#1'LPT3'#1'COM2'#1'COM3'#1'COM4'#1'CONIN$'#1'CONOUT$'
    + #1'COM5'#1'COM6'#1'COM7'#1'COM8'#1'COM9'#1'LPT1'#1'LPT2'#1'LPT3'#1'LPT4'#1'LPT5'#1'LPT6'#1'LPT7'#1'LPT8'#1'LPT9'#1;
var
  F: THandle;
  FT: DWord;
  I: Integer;
  FileNameExpanded, s: AnsiString;
begin
  s := UpperCase(ExtractFileName(FN));
  if s = '' then
  begin
    Result := False;
    Exit;
  end;
  I := Pos(CDot, s);
  if I > 0 then
    Delete(s, I, Length(s) - I + 1);
  Result := (s = '') or (Pos(#1 + s + #1, fDevices) = 0);
  if Result then
  begin
    FileNameExpanded := ExpandFileName(FN);
    if FileNameExpanded = '' then
    begin
      F := Invalid_Handle_Value
    end else
    begin
      F := Windows.CreateFileA(@(FileNameExpanded[1]), 0,
        FILE_SHARE_WRITE or FILE_SHARE_READ, nil, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, 0);
    end;
    if F <> Invalid_Handle_Value then
    begin
      FT := GetFileType(F);
      Result := (FT = FILE_TYPE_DISK) or (FT = FILE_TYPE_UNKNOWN);
      CloseHandle(F);
    end;
  end;
end;



function LocalFNameSafe(const AFName: AnsiString): Boolean;
var
  ParentDir, Dir, FName: AnsiString;
  fa: DWORD;
begin
  Result := False;

  ParentDir := AFName;
  repeat
    Dir := ExtractFileDir(ParentDir);
    if (Dir = ParentDir) or (not (Length(Dir) < Length(ParentDir))) then
    begin
      Break;
    end;

    if (Length(Dir) <= 4) and StrEnds(Dir, ':\') then
    begin
      Result := True;
      Break;
    end;

    FName := ExtractFileName(ParentDir);
    if (FName <> '') and (not FileIsRegular(FName)) then
    begin
      Break;
    end;
    if Dir = '' then
    begin
      fa := INVALID_VALUE;
    end else
    begin
      fa := GetFileAttributesA(@(Dir[1]));
    end;
    if fa = INVALID_VALUE then
    begin
      Break;
    end;
    if ((fa and FILE_ATTRIBUTE_DIRECTORY) = 0) or
       ((fa and FILE_ATTRIBUTE_HIDDEN) <> 0) or
       ((fa and FILE_ATTRIBUTE_SYSTEM) <> 0) then
    begin
      Break;
    end;
    ParentDir := Dir;

  until False;
end;


function WebServerHttpResponse(thr: THttpServerThread; d: THTTPData): TAbstractHttpResponseData;
var
  sPath, sName, sExt,
  s: AnsiString;
  LocalFName: AnsiString;
  ii: HInst;
  ResponseEntityHeader: TEntityHeader;


var
  CgiFile: AnsiString;
  PathInfo: AnsiString;

  // Thanks to Nick McDaniel, Intranaut Inc. (21 January 1999)
  // We were having problems with files that that had spaces in the name (C:\Program Files\).  The error that was being generated was "Internal Server Error: Can't open
  // To alievate this problem, we added double quotes to executable and script name

function QuoteSpaced(const s: AnsiString): AnsiString;
var
  CSpace: AnsiChar;
begin
// Thanks to Vladimir A. Bakhvaloff (30 January 2000)
// parameters to Pos() function were improperly ordered
  CSpace := ' ';
  if Pos(CSpace, DelSpaces(s)) <= 0 then // Does the file name contain space cheracters inside?
  begin
    Result := s                 // No, return it as is
  end else
  begin
    Result := '"'+s+'"';        // Yes, add quotes
  end;
end;

procedure Exec;
begin
  ResponseEntityHeader := ExecuteScript(QuoteSpaced(s), sPath, QuoteSpaced(CgiFile), d.URIQueryParam, GetEnvStr(thr, d, PathInfo), d.RequestEntityHeader.EntityBody, thr.Buffer, thr, d.ErrorMsg);
end;


function CgiFileOK: Boolean;
var
  fa: DWord;
  z,ts,comb: AnsiString;
begin
  Result := False;
  comb := ParamStr1+'\'+ScriptsPath;
  fa := GetFileAttributesA(@(comb[1]));
  if fa = INVALID_HANDLE_VALUE then Exit;
  if ((fa and FILE_ATTRIBUTE_DIRECTORY) = 0) or
     ((fa and FILE_ATTRIBUTE_HIDDEN) <> 0) or
     ((fa and FILE_ATTRIBUTE_SYSTEM) <> 0)
   then Exit;
  CgiFile := Copy(LocalFName, 1, Length(ParamStr1)+1+Length(ScriptsPath));
  PathInfo := CopyLeft(LocalFName, Length(CgiFile)+2);
  ts := PathInfo;
  repeat
    GetWrd(ts, z, '\');
    CgiFile := CgiFile + '\'+z;
    fa := GetFileAttributesA(@(CgiFile[1]));
    if fa = INVALID_HANDLE_VALUE then Exit;
    if ((fa and FILE_ATTRIBUTE_DIRECTORY) = 0) and
       ((fa and FILE_ATTRIBUTE_HIDDEN) = 0) and
       ((fa and FILE_ATTRIBUTE_SYSTEM) = 0) then
    begin
      Result := True;
      Exit;
    end;
  until False;
end;

procedure RunCGI;
begin
    FSplit(CgiFile, sPath, sName, sExt);
    if UpperCase(sExt) = '.EXE' then
    begin
      s := CgiFile;
      Exec;
    end else
    begin
      ii := FindExecutableCached(CgiFile, sPath, s);
      if ii > 32 then
      begin
        if not FileExists(s) then
        begin
          d.ErrorMsg := SysErrorMsg(GetLastError) + ' ('+s+')';
        end else
        begin
          Exec;
        end;
      end else
      begin
        if ii = 31 then
        begin
          s := CgiFile;
          Exec;
        end else
        begin
          d.ErrorMsg := SysErrorMsg(ii);
        end;
      end;
    end;
end;

procedure MakeHeaders;
begin
  if ResponseEntityHeader = nil then
  begin
    if d.ErrorMsg = '' then
    begin
      d.ErrorMsg := 'CGI script '+d.URIPath+' returned nothing';
    end else
    begin
      d.ErrorMsg := 'Internal Server Error: '+d.ErrorMsg;
    end;
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
end;


var
  CForwardSlash, CBackSlash, CZero, CSemicolon: AnsiChar;
  IsCGI: Boolean;
  CheckedURI, CDoubleDot, CDoubleBackslash, CDotEncosed: AnsiString;
begin
  CBackSlash := '\';
  CForwardSlash := '/';
  ResponseEntityHeader := nil;
  s := d.URIPath;

  if Pos(CBackSlash, s) > 0 then
  begin
    Result := THttpResponseErrorCode.Create(403);
    Exit;
  end;

  Replace(CForwardSlash, CBackSlash, s);
  if (s='') or (s[1]<>CBackSlash) then
  begin
    Result := THttpResponseErrorCode.Create(403);
    Exit;
  end;
  CZero := #0;
  CSemicolon := ':';
  CDoubleDot := '..';
  CDoubleBackslash := '\\';
  CDotEncosed := '\.\';
  if (Pos(CZero, s)>0) or
     (Pos(CDoubleDot, s)>0) or
     (Pos(CSemicolon,s)>0) or
     (Pos(CDotEncosed, s) > 0) or  // level #1 of protection from \.\
     (Pos(CDoubleBackslash,s)>0) then
  begin
    Result := THttpResponseErrorCode.Create(403);
    Exit;
  end;

  LocalFName := ExpandFileName(ParamStr1 + s);

  if not StrEnds(LocalFName, s) then      // level #2 of protection from \.\
  begin
    Result := THttpResponseErrorCode.Create(403);
    Exit;
  end;

  if not LocalFNameSafe(LocalFName) then
  begin
    Result := THttpResponseErrorCode.Create(403);
    Exit;
  end;

  CheckedURI := s;


// Analyze file extension
  if LowerCase(Copy(d.URIPath, 2, Length(ScriptsPath)+1)) = (ScriptsPath + '/') then
  begin
    if CgiFileOK then RunCGI else d.ErrorMsg := SysErrorMsg(GetLastError);
    MakeHeaders;
    Exit;
  end;

  if CheckedURI[Length(CheckedURI)]='\' then
  begin
    LocalFName := FindRootFile(CheckedURI, IsCGI);
    if IsCGI then
    begin
      CgiFile := LocalFName;
      RunCGI;
      MakeHeaders;
      Exit;
    end;
  end else
  if ExtractFileExt(CheckedURI) = '' then
  begin
    Result := ReturnNewLocation(d.URIpath+'/', d);
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
  FPOS: DWORD;
  i, j: Integer;
  s,z,k: AnsiString;
  d: THTTPData;
  AbortConnection: Boolean;
  v, Actually: DWORD;
  CQuestion, CEqual, CZero, CSemicolon: AnsiChar;
begin

  {$IFDEF BEHIND_TUNNEL}
  if recv(Socket.Handle, Socket.FAddr, 4, 0) <> 4 then Exit;
  {$ENDIF}


  if not Socket.Handshake then Exit;

  RemoteAddr := AddrInet(Socket.FAddr);
  RemoteHost := GetHostNameByAddr(Socket.FAddr);

  repeat
    AbortConnection := False;
    d := THTTPData.Create;
    d.StatusCode := 400;
    d.ReportError := True;
    d.ResponseGeneralHeader := TGeneralHeader.Create;
    if d.ResponseResponseHeader = nil then d.ResponseResponseHeader := TResponseHeader.Create;
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

      KeepAliveInRequest := UpperCase(RequestGeneralHeader.Connection) = 'KEEP-ALIVE';
      KeepAliveInReply := KeepAliveInRequest;

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
        CQuestion := '?';
        i := Pos(CQuestion, s);
        if i > 0 then
        begin
          URIQuery := CopyLeft(s, i+1);
          DeleteLeft(s, i);
          CEqual := '=';
          if Pos(CEqual, URIQuery) = 0 then
          begin
            URIQueryParam := URIQuery;
            if not UnpackPchars(URIQueryParam) then Break;
            CZero := #0;
            if Pos(CZero, URIQueryParam)>0 then Break;
          end;
        end;
        CSemicolon := ';';
        i := Pos(CSemicolon, s);
        if i > 0 then
        begin
          URIParams := CopyLeft(s, i+1);
          DeleteLeft(s, i);
        end;
        if not UnpackPchars(s) then Break;
        URIPath := s;

{$IFDEF LOGGING}
        AddRefererLog(d.RequestRequestHeader.Referer, d.URIPath);
        AddAgentLog(d.RequestRequestHeader.UserAgent);
{$ENDIF}
        PrepareResponse(d);

        Break;
      end;
    until False;

  // Send a response
    with d do
    begin
      if ResponseEntityHeader = nil then ResponseEntityHeader := TEntityHeader.Create;

      if TransferFile and (RequestRequestHeader.IfModifiedSince <> '') then
      begin
        Actually := StrToFileTime(RequestRequestHeader.IfModifiedSince);
        if (Actually <> INVALID_FILE_TIME) and (StrToFileTime(ResponseEntityHeader.LastModified) = Actually) then
        begin
          ZeroHandle(FHandle);
          TransferFile := False;
          StatusCode := 304;
          ReportError := True;
        end;
      end;

      s := ResponseEntityHeader.CGIStatus;
      if s <> '' then
      begin
	      k := s;
	      GetWrd(k, z, ' ');
        v := Vl(z);
        if (v <> INVALID_VALUE) and (v < 1000) and (v > 0) then StatusCode := v else StatusCode := 0;
    // Status code 200 was treated as error. Thanks to David Gommeren for pointing that out.
      	if StatusCode <> 200 then ReportError := True;
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
        if StatusCode = 401 then
        begin
          if ResponseResponseHeader.IsNormalAuthenticateAfterEmptyUsernamePassword then
          begin
            // don't close connection on "Unauthorized" error if the username and password were emplty - a normal way of authenticate on http
          end else
          begin
            // invalid credentials - sleep from 0 to 5 seconds to prevent password checking
            Sleep(Random(5001));
            KeepAliveInReply := False;
          end;
        end else
        begin
          KeepAliveInReply := False;
        end;
        if ResponseEntityHeader.ContentType = '' then ResponseEntityHeader.ContentType := 'text/html';
        if ResponseEntityHeader.EntityBody = '' then ResponseEntityHeader.EntityBody :=
          '<HTML>'+
          '<TITLE>'+s+'</TITLE>'+
          '<BODY><H1>'+ErrorMsg+'</H1></BODY>'+
          '</HTML>';
        ResponseEntityHeader.EntityLength := Length(ResponseEntityHeader.EntityBody);
      end;

      ResponseEntityHeader.ContentLength := ItoS(ResponseEntityHeader.EntityLength);

      if KeepAliveInReply then ResponseGeneralHeader.Connection := 'Keep-Alive' else
      begin
        if KeepAliveInRequest then ResponseGeneralHeader.Connection := 'Close';
      end;

      ResponseResponseHeader.Server := CServerName;

      if ReportError then i := -1 else i := ResponseEntityHeader.EntityLength;
{$IFDEF LOGGING}
      AddAccessLog(RemoteHost, Method + ' ' + URIPath, HTTPVersion, d.AuthUser, StatusCode,  i);
{$ENDIF}
      s := 'HTTP/1.0 '+ s + #13#10+
        ResponseGeneralHeader.OutString+
        ResponseResponseHeader.OutString+
        ResponseEntityHeader.OutString+
        #13#10;

      if TransferFile then
      begin
        Socket.WriteStr(s);
        FPOS := 0;
        repeat
          ReadFile(FHandle, Buffer, CHTTPServerThreadBufSize, Actually, nil);
          Inc(FPOS, Actually);
          if FPOS > FileNfo.Size then Break;
          if Actually = 0 then Break;
          Actually := Socket.Write(Buffer, Actually);
        until (FPOS = FileNfo.Size) or (Actually < CHTTPServerThreadBufSize) or (Socket.Status <> 0);
        if FPOS <> FileNfo.Size then AbortConnection := True;
        ZeroHandle(FHandle);
      end else
      begin
        s := s + ResponseEntityHeader.EntityBody;
        Socket.WriteStr(s);
      end;
      AbortConnection := AbortConnection or not KeepAliveInReply;
    end;
    FreeObject(d);
  until AbortConnection
end;


function TContentTypeColl.Compare(Key1, Key2: Pointer): Integer;
begin
  Compare := CompareStr(PAnsiString(Key1)^, PAnsiString(Key2)^);
end;

function TContentTypeColl.KeyOf(Item: Pointer): Pointer;
begin
  Result := @TContentType(Item).Extension;
end;

procedure GetContentTypes(const CBase, SubName: AnsiString; Swap: Boolean);
const
  ClassBufSize = 1000;
var
  Buf: array[0..ClassBufSize] of AnsiChar;
  r: TContentType;
  s, z, t : AnsiString;
  ec,
  i: Integer;
  Key,
  SubKey,
  BufSize,                       // size of AnsiString buffer
  cSubKeys,                      // number of subkeys
  cchMaxSubkey,                  // longest subkey name length
  cchMaxClass,                   // longest class AnsiString length
  cValues,                       // number of value entries
  cchMaxValueName,               // longest value name length
  cbMaxValueData,                // longest value data length
  cbSecurityDescriptor: DWORD;   // security descriptor length
  ftLastWriteTime: TFileTime;    // last write time
begin
  Key := OpenRegKeyEx(CBase, KEY_QUERY_VALUE or KEY_ENUMERATE_SUB_KEYS);
  BufSize := ClassBufSize;
  ec := RegQueryInfoKeyA(
    Key,                        // handle of key to query
    @(Buf[0]),
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
    ec := RegEnumKeyExA(
      Key,
      i,
      Buf,
      BufSize,
      nil,
      nil, // address of buffer for class AnsiString
      nil, // address for size of class buffer
      @ftLastWriteTime);
    if ec <> ERROR_SUCCESS then Continue;
    SetString(s, Buf, BufSize);
    SubKey := OpenRegKey(CBase+'\'+s);
    if SubKey = INVALID_REGISTRY_KEY then Continue;
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


function Adr2IntGet(const s: AnsiString; var CPos: Integer; var Error: Boolean): Byte;
var
  C: AnsiChar;
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


function _Adr2Int(const s: AnsiString): DWORD;
var
  CPos: Integer;
  Error: Boolean;
  A: TAdrB;
begin
  Error := False;
  CPos := 1;
  A.A := Adr2IntGet(s, CPos, Error);
  A.B := Adr2IntGet(s, CPos, Error);
  A.C := Adr2IntGet(s, CPos, Error);
  A.D := Adr2IntGet(s, CPos, Error);
  if Error then Result := DWORD(INADDR_NONE) else  Result := PInteger(@A)^;
end;

function Adr2Int(const s: AnsiString): Integer;
begin
  Result := _Adr2Int(s+'.');
end;


var
  BindPort, BindAddr: DWORD;
  IsCGI: Boolean;

function GetHomeDir: Boolean;
var
  s: AnsiString;
  i: DWORD;
begin
  Result := False;
  if ParamCount < 1 then
  begin
    MessageBox(0, 'Path to home directory is absent!'#13#10+
                  CServerName+' failed to start.',
                  CServerName, CMB_FAILED);
    Exit;
  end;
  ParamStr1 := UnicodeStringToRawByteString(ParamStr(1), GetACP);
  if ParamStr1[Length(ParamStr1)] = '\' then Delete(ParamStr1, Length(ParamStr1), 1);
  s := FindRootFile('\', IsCGI);
  if not FileExists(s) then
  begin
    s := 'Access to "'+s+'" failed'#13#10'Reason: "'+SysErrorMsg(GetLastError)+'"'#13#10#13#10+
    CServerName+' failed to start';
    MessageBoxA(0, @(s[1]), CServerName, CMB_FAILED);
    Exit;
  end;
  BindPort := 80;
  BindAddr := _INADDR_ANY;
  if ParamCount > 1 then
  begin
    i := Vl(UnicodeStringToRawByteString(ParamStr(2), GetACP));
    if i <> INVALID_VALUE then BindPort := i;
  end;
  if ParamCount > 2 then
  begin
    i := Adr2Int(UnicodeStringToRawByteString(ParamStr(3), GetACP));
    if i <> INVALID_VALUE then BindAddr := i;
  end;
  Result := True;
end;

procedure ReadContentTypes;
begin
  ContentTypes := TContentTypeColl.Create;
  GetContentTypes('SOFTWARE\Classes\MIME\Database\Content Type', 'Extension', False);
  GetContentTypes('SOFTWARE\Classes', 'Content Type', True);
end;

{$IFDEF LOGGING}
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
{$ENDIF}

procedure InitReseterThread;
begin
  SocketsColl := TColl.Create;
  ResetterThread := TResetterThread.Create;
end;

procedure FreeDummyLibraries;
var
  I: Integer;
begin
  I := GetModuleHandle('OleAut32'); if I <> 0 then FreeLibrary(I); 
  I := GetModuleHandle('Ole32'); if I <> 0 then FreeLibrary(I);
  I := GetModuleHandle('RPCRT4'); if I <> 0 then FreeLibrary(I);
  I := GetModuleHandle('AdvAPI32'); if I <> 0 then FreeLibrary(I);
  I := GetModuleHandle('GDI32'); if I <> 0 then FreeLibrary(I);
  I := GetModuleHandle('COMCTL32'); if I <> 0 then FreeLibrary(I);
  I := GetModuleHandle('USER32'); if I <> 0 then FreeLibrary(I);
end;

type
  TWndMethod = procedure(var Message: TMessage) of object;


const
  InstanceCount = 313;

{ Object instance management }

type
  PObjectInstance = ^TObjectInstance;
  TObjectInstance = packed record
    Code: Byte;
    Offset: Integer;
    case Integer of
      0: (Next: PObjectInstance);
      1: (Method: TWndMethod);
  end;

type
  PInstanceBlock = ^TInstanceBlock;
  TInstanceBlock = packed record
    Next: PInstanceBlock;
    Code: array[1..2] of Byte;
    WndProcPtr: Pointer;
    Instances: array[0..InstanceCount] of TObjectInstance;
  end;

var
  InstBlockList: PInstanceBlock;
  InstFreeList: PObjectInstance;

{$IFDEF FPC}
{$ASMMODE Intel}
{$ENDIF}


{ Standard window procedure }
{ In    ECX = Address of method pointer }
{ Out   EAX = Result }

function StdWndProc(Window: HWND; Message, WParam: Longint;
  LParam: Longint): Longint; stdcall; assembler;
asm
        XOR     EAX,EAX
        PUSH    EAX
        PUSH    LParam
        PUSH    WParam
        PUSH    Message
        MOV     EDX,ESP
        MOV     EAX,[ECX].Longint[4]
        CALL    [ECX].Pointer
        ADD     ESP,12
        POP     EAX
end;

{ Allocate an object instance }

function CalcJmpOffset(Src, Dest: Pointer): Longint;
begin
  Result := Longint(Dest) - (Longint(Src) + 5);
end;

function MakeObjectInstance(Method: TWndMethod): Pointer;
const
  BlockCode: array[1..2] of Byte = (
    $59,       { POP ECX }
    $E9);      { JMP StdWndProc }
  PageSize = 4096;
var
  Block: PInstanceBlock;
  Instance: PObjectInstance;
begin
  if InstFreeList = nil then
  begin
    Block := VirtualAlloc(nil, PageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    Block^.Next := InstBlockList;
    Move(BlockCode, Block^.Code, SizeOf(BlockCode));
    Block^.WndProcPtr := Pointer(CalcJmpOffset(@Block^.Code[2], @StdWndProc));
    Instance := @(Block^.Instances[0]);
    repeat
      Instance^.Code := $E8;  { CALL NEAR PTR Offset }
      Instance^.Offset := CalcJmpOffset(Instance, @Block^.Code);
      Instance^.Next := InstFreeList;
      InstFreeList := Instance;
      Inc(Longint(Instance), SizeOf(TObjectInstance));
    until Longint(Instance) - Longint(Block) >= SizeOf(TInstanceBlock);
    InstBlockList := Block;
  end;
  Result := InstFreeList;
  Instance := InstFreeList;
  InstFreeList := Instance^.Next;
  Instance^.Method := Method;
end;

{ Free an object instance }

procedure FreeObjectInstance(ObjectInstance: Pointer);
begin
  if ObjectInstance <> nil then
  begin
    PObjectInstance(ObjectInstance)^.Next := InstFreeList;
    InstFreeList := ObjectInstance;
  end;
end;

var
  UtilWindowClass: TWndClass = (
    style: 0;
    lpfnWndProc: @DefWindowProc;
    cbClsExtra: 0;
    cbWndExtra: 0;
    hInstance: 0;
    hIcon: 0;
    hCursor: 0;
    hbrBackground: 0;
    lpszMenuName: nil;
    lpszClassName: 'TPUtilWindow');

function AllocateHWnd(Method: TWndMethod): HWND;
var
  TempClass: TWndClass;
  ClassRegistered: Boolean;
begin
  UtilWindowClass.hInstance := HInstance;
  UtilWindowClass.lpfnWndProc := @DefWindowProc;
  ClassRegistered := GetClassInfo(HInstance, UtilWindowClass.lpszClassName,
    TempClass);
  if not ClassRegistered or (TempClass.lpfnWndProc <> @DefWindowProc) then
  begin
    if ClassRegistered then
      Windows.UnregisterClass(UtilWindowClass.lpszClassName, HInstance);
    Windows.RegisterClass(UtilWindowClass);
  end;
  Result := CreateWindowEx(WS_EX_TOOLWINDOW, UtilWindowClass.lpszClassName,
    '', WS_POPUP {!0}, 0, 0, 0, 0, 0, 0, HInstance, nil);
  if Assigned(Method) then
    SetWindowLong(Result, GWL_WNDPROC, Longint(MakeObjectInstance(Method)));
end;

procedure DeallocateHWnd(Wnd: HWND);
var
  DefAddr, Instance: Pointer;
begin
  Instance := Pointer(GetWindowLong(Wnd, GWL_WNDPROC));
  DestroyWindow(Wnd);
  DefAddr := @DefWindowProc;
  if Instance <> DefAddr then FreeObjectInstance(Instance);
end;

type
  TWndProc = class
    Handle: THandle;
    procedure WndProc(var M: TMessage);
    destructor Destroy; override;
  end;

destructor TWndProc.Destroy;
begin
  DeallocateHWnd(Handle);
  inherited Destroy;
end;

var
  Leave: Boolean;

procedure TWndProc.WndProc(var M: TMessage);
begin
  if M.Msg = WM_QUIT then Leave := True;
  M.Result := DefWindowProc(Handle, M.Msg, M.wParam, M.lParam);
end;

type
  TMainThread = class(TThread)
    procedure Execute; override;
  end;

var
  ServerSocketHandle: WinSock.TSocket;


procedure MainLoop;
var
  J, err: Integer;
  NewSocketHandle: WinSock.TSocket;
  NewSocket: TSocket;
  NewThread: THTTPServerThread;
  WData: TWSAData;
  Addr: TSockAddr;
  s: AnsiString;
begin
  Leave := False;
  err := WSAStartup(MakeWord(1,1), WData);
  if err <> 0 then
  begin
    s := 'Failed to initialize WinSocket,error #'+ItoS(err);
    MessageBoxA(0, @(s[1]), CServerName, CMB_FAILED);
    Halt;
  end;
  ServerSocketHandle := socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if ServerSocketHandle = INVALID_SOCKET then
  begin
    s := 'Failed to create a socket, Error #'+ItoS(WSAGetLastError);
    MessageBoxA(0, @(s[1]), CServerName, CMB_FAILED);
    Halt;
  end;

  Addr.sin_family := AF_INET;
  Addr.sin_port := htons(BindPort);
  Addr.sin_addr.s_addr := BindAddr;
  if bind(ServerSocketHandle, Addr, SizeOf(Addr)) = SOCKET_ERROR then
  begin
    MessageBeep(MB_ICONEXCLAMATION);
{$IFDEF LOGGING}
    AddErrorLog(
         'Failed to bind the socket, port #'+ItoS(BindPort)+', address='+AddrInet(BindAddr)+', error #'+ItoS(WSAGetLastError)+'.'#13#10#13#10+
         'Probable reason is that another daemon is already running on the same port ('+ItoS(BindPort)+').');
{$ENDIF}
    Halt;
  end;



  InitReseterThread;

  listen(ServerSocketHandle, 100);

  FreeDummyLibraries;

  repeat
    J := SizeOf(Addr);
    {$IFDEF VER90}
    NewSocketHandle := accept(ServerSocketHandle, Addr, J);
    {$ELSE}
    NewSocketHandle := accept(ServerSocketHandle, @Addr, @J);
    {$ENDIF}
    if NewSocketHandle = INVALID_SOCKET then Break;

    if Leave then Break;

    NewSocket := TSocket.Create;
    NewSocket.Handle := NewSocketHandle;
    NewSocket.FAddr := Addr.sin_addr.s_addr;
    NewSocket.FPort := Addr.sin_port;
    if not NewSocket.Startup then FreeObject(NewSocket) else
    begin
      SocketsColl.Enter;
      if SocksCount = 0 then
      begin
        ResetterThread.TimeToSleep := SleepQuant;
        SetEvent(ResetterThread.oSleep);
      end;
      Inc(SocksCount);
      SocketsColl.Leave;
      NewThread := THTTPServerThread.Create;
      NewThread.FreeOnTerminate := True;
      NewThread.Socket := NewSocket;
      NewSocket.RegisterSelf;
      NewThread.Resume;
    end;
  until False;
  if ServerSocketHandle <> INVALID_SOCKET then CloseSocket(ServerSocketHandle);
end;


procedure MessageLoop;
var
  M: TMsg;
  WP: TWndProc;
begin
  WP := TWndProc.Create;
  WP.Handle := AllocateHWnd({$IFDEF FPC}@{$ENDIF}WP.WndProc);
  repeat
    GetMessage(M, 0, 0, 0);
    if M.Message = WM_QUIT then
    begin
      Leave := True;
      Break;
    end;
    TranslateMessage(M);
    DispatchMessage(M);
  until Leave;
  WP.Free;
end;


procedure ComeOn;
var
  i: Integer;
  MainThread: TMainThread;
begin

//--- Set Hight priority class
//  SetPriorityClass(GetCurrentProcess, HIGH_PRIORITY_CLASS);

{$IFDEF ODBC}
  InitializeCriticalSection(OdbcCS);
{$endif}

//--- Initialize xBase Module
  xBaseInit;

  ExecutableCache := TExecutableCacheColl.Create;
  ExecutableCache.Enter;
  ExecutableCache.Leave;

  RootCacheColl := TRootCacheColl.Create;
  RootCacheColl.Enter;
  RootCacheColl.Leave;

//--- Get and validate a home directory
  if not GetHomeDir then Exit;



//--- Read content types from registry and associate with file extensions
  ReadContentTypes;

// --- Open log files and initialize semaphores
{$IFDEF LOGGING}
  InitLogs;
{$ENDIF}

// --- Perform main loop
  MainThread := TMainThread.Create(False);

  MessageLoop;

  CloseSocket(ServerSocketHandle);
  ServerSocketHandle := INVALID_SOCKET;

  MainThread.Terminate;
  WaitForSingleObject(MainThread.Handle, INFINITE);
  MainThread.Free;


// Non-debug version never exits :-)

  ResetterThread.Terminate;
  SetEvent(ResetterThread.oSleep);
  SocketsColl.Enter;
  for i := 0 to SocketsColl.Count-1 do shutdown(TSocket(SocketsColl[i]).Handle, 2);
  SocketsColl.Leave;
  while SocketsColl.Count > 0 do Sleep(1000);
  ResetterThread.TimeToSleep := SleepQuant;
  SetEvent(ResetterThread.oSleep);
  WaitForSingleObject(ResetterThread.Handle, INFINITE);
  FreeObject(ResetterThread);
  FreeObject(SocketsColl);
  FreeObject(ContentTypes);
  xBaseDone;
{$IFDEF LOGGING}
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

{ TMsgThread }


{ TMainThread }

procedure TMainThread.Execute;
begin
  MainLoop;
end;

end.


