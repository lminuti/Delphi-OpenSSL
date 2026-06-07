{******************************************************************************}
{                                                                              }
{  Delphi OPENSSL Library                                                      }
{  Copyright (c) Luca Minuti                                                   }
{  https://bitbucket.org/lminuti/delphi-openssl                                }
{                                                                              }
{******************************************************************************}
{                                                                              }
{  Licensed under the Apache License, Version 2.0 (the "License");             }
{  you may not use this file except in compliance with the License.            }
{  You may obtain a copy of the License at                                     }
{                                                                              }
{      http://www.apache.org/licenses/LICENSE-2.0                              }
{                                                                              }
{  Unless required by applicable law or agreed to in writing, software         }
{  distributed under the License is distributed on an "AS IS" BASIS,           }
{  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    }
{  See the License for the specific language governing permissions and         }
{  limitations under the License.                                              }
{                                                                              }
{******************************************************************************}
unit OpenSSL.Core;

interface

{$I OpenSSL.inc}

uses
  System.Classes, System.SysUtils, System.StrUtils,
  {$IFNDEF USE_TAURUS_TLS}
  OpenSSL.libeay32, IdSSLOpenSSLHeaders;
  {$ELSE}
  TaurusTLSHeaders_types, TaurusTLSHeaders_evp,
  TaurusTLSHeaders_bio, TaurusTLSHeaders_rand,
  TaurusTLSHeaders_bn, TaurusTLSHeaders_x509,
  TaurusTLSHeaders_err, TaurusTLSLoader;
  {$ENDIF}

type
  {$IFDEF USE_TAURUS_TLS}
  TIdC_LONG  = LongInt;
  TIdC_INT   = Integer;
  SIZE_T = NativeUInt;

  {$ENDIF}

  TRASPadding = (
    rpPKCS,           // use PKCS#1 v1.5 padding (default),
    rpOAEP,           // use PKCS#1 OAEP
    rpSSL,            // use SSL v2 padding
    rpRAW             // use no padding
    );

  // X.509 Subject/Issuer information
  // String format (OpenSSL command line style): /C=IT/ST=Lombardia/L=Milan/O=MyOrg/CN=localhost
  // Implicit conversions support bidirectional parsing and formatting
  TSubjectInfo = record
  private
    FCommonName: string;
    FOrganization: string;
    FOrganizationalUnit: string;
    FCountry: string;
    FState: string;
    FLocality: string;
    FEmailAddress: string;
  public
    class operator Implicit(const Value: string): TSubjectInfo;
    class operator Implicit(const Value: TSubjectInfo): string;

    constructor Create(const Value: string; Delimiter: Char);

    property CommonName: string read FCommonName write FCommonName;
    property Organization: string read FOrganization write FOrganization;
    property OrganizationalUnit: string read FOrganizationalUnit write FOrganizationalUnit;
    property Country: string read FCountry write FCountry;
    property State: string read FState write FState;
    property Locality: string read FLocality write FLocality;
    property EmailAddress: string read FEmailAddress write FEmailAddress;
  end;

  // X.509 Serial Number
  TSerialNumber = record
  private
    FData: TBytes;
  public
    class operator Implicit(const Value: TSerialNumber): string;
    class operator Implicit(const Value: string): TSerialNumber;
    class operator Implicit(const Value: TSerialNumber): Int64;
    class operator Implicit(const Value: Int64): TSerialNumber;
    class operator Implicit(const Value: TBytes): TSerialNumber;

    function ToHexString(Separator: Char = #0): string;
    function ToInt64: Int64;
    function TryToInt64(out Value: Int64): Boolean;
    function IsEmpty: Boolean;

    property Data: TBytes read FData;
  end;

  EOpenSSLError = class(Exception)
  end;

  EOpenSSLLibError = class(EOpenSSLError)
  private
    FErrorCode: Integer;
  public
    constructor Create(Code :Integer; const Msg: string);
    property ErrorCode :Integer read FErrorCode;
  end;

  TOpenSLLBase = class
  public
    class procedure CheckOpenSSLLibrary; static;
    constructor Create; virtual;
  end;

const
  SALT_MAGIC: AnsiString = 'Salted__';
  SALT_MAGIC_LEN: integer = 8;
  SALT_SIZE = 8;

function GetOpenSSLErrorMessage: string;

procedure RaiseOpenSSLError(const AMessage :string = '');

function EVP_GetSalt: TBytes;

procedure EVP_GetKeyIV(APassword: TBytes; ACipher: PEVP_CIPHER; const ASalt: TBytes; out Key, IV: TBytes); overload;

// Password will be encoded in UTF-8 if you want another encodig use the TBytes version
procedure EVP_GetKeyIV(APassword: string; ACipher: PEVP_CIPHER; const ASalt: TBytes; out Key, IV: TBytes); overload;

function Base64Encode(InputBuffer :TBytes) :TBytes;
function Base64Decode(InputBuffer :TBytes) :TBytes;

function BIO_read(b: PBIO; var OutputBuffer :TBytes): Integer;
function BIO_get_mem_data(b : PBIO; pp : Pointer) : Integer;
function BIO_new_mem_buf(InputBuffer :TBytes): PBIO;

// Provided for both backends: the Indy header bundled with some Delphi versions
// declares BIO_get_md_ctx with a by-value parameter, which leaves the caller's
// EVP_MD_CTX pointer uninitialized (it must receive the context by reference).
function BIO_get_md_ctx(b : PBIO; var mdcp : PEVP_MD_CTX) : LongInt;

{$IFDEF USE_TAURUS_TLS}
function BIO_flush(b : PBIO) : TIdC_INT;
function BIO_to_string(b : PBIO; Encoding: TEncoding): string; overload;
function BIO_to_string(b : PBIO): string; overload;
function BIO_pending(b : PBIO) : TIdC_INT;

function EVP_MD_CTX_create : PEVP_MD_CTX;
function EVP_MD_CTX_init(ctx: PEVP_MD_CTX): TIdC_INT;
procedure EVP_MD_CTX_destroy(ctx: PEVP_MD_CTX);
function EVP_DigestSignUpdate(a : PEVP_MD_CTX; b : Pointer; c : SIZE_T) : TIdC_Int;
function EVP_DigestVerifyUpdate(a : PEVP_MD_CTX; b : Pointer; c : size_t) : TIdC_INT;

function BN_num_bytes(a: PBIGNUM): Integer;

function X509_get_notBefore(x509: PX509):PASN1_TIME;
function X509_get_notAfter(x509: PX509):PASN1_TIME;
{$ENDIF}

function EVP_DecryptUpdate(ctx: PEVP_CIPHER_CTX; data_out: PByte; var outl: integer; data_in: PByte; inl: integer): integer;
function EVP_DecryptFinal(ctx: PEVP_CIPHER_CTX; data_out: PByte; var outl: integer): integer;
function EVP_DecryptFinal_ex(ctx : PEVP_CIPHER_CTX; outm: PByte; var outl : integer) : integer;
function EVP_EncryptUpdate(ctx : PEVP_CIPHER_CTX; _out : PByte; var outl : integer; _in : PByte; inl : integer): integer;
function EVP_EncryptFinal_ex(ctx : PEVP_CIPHER_CTX; _out : PByte; var outl : integer) : integer;
function EVP_DecryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): integer;
function EVP_EncryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): integer;

function LoadOpenSSLLibrary: boolean;
procedure UnLoadOpenSSLLibrary;

implementation

function LoadOpenSSLLibrary: boolean;
begin
  {$IFNDEF USE_TAURUS_TLS}
  Result := OpenSSL.libeay32.LoadOpenSSLLibraryEx;
  {$ELSE}
  Result := GetOpenSSLLoader.Load;
  {$ENDIF}
end;

procedure UnLoadOpenSSLLibrary;
begin
  {$IFNDEF USE_TAURUS_TLS}
  OpenSSL.libeay32.UnLoadOpenSSLLibraryEx;
  {$ELSE}
  GetOpenSSLLoader.Unload;
  {$ENDIF}
end;

function BIO_get_md_ctx(b : PBIO; var mdcp : PEVP_MD_CTX) : LongInt; {$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := BIO_ctrl(b,BIO_C_GET_MD_CTX,0,@mdcp);
end;

{$IFDEF USE_TAURUS_TLS}
function BIO_flush(b : PBIO) : TIdC_INT; {$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := BIO_ctrl(b,BIO_CTRL_FLUSH,0,nil);
end;

function EVP_MD_CTX_create : PEVP_MD_CTX; {$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := EVP_MD_CTX_new;
end;

function EVP_MD_CTX_init(ctx: PEVP_MD_CTX): TIdC_INT; {$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := EVP_MD_CTX_reset(ctx);
end;

procedure EVP_MD_CTX_destroy(ctx: PEVP_MD_CTX); {$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  EVP_MD_CTX_free(ctx);
end;

function EVP_DigestSignUpdate(a : PEVP_MD_CTX; b : Pointer; c : SIZE_T) : TIdC_Int; {$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := EVP_DigestUpdate(a,b,SIZE_T(c));
end;

function EVP_DigestVerifyUpdate(a : PEVP_MD_CTX; b : Pointer; c : size_t) : TIdC_INT; {$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := EVP_DigestUpdate(a,b,size_t(c));
end;

function BIO_to_string(b : PBIO; Encoding: TEncoding): string; overload;
const
  BuffSize = 1024;
var
  Buffer: TBytes;
begin
  Result := '';
  SetLength(Buffer, BuffSize);
  while BIO_read(b, buffer) > 0 do
  begin
    Result := Result + Encoding.GetString(Buffer);
  end;
end;

function BIO_to_string(b : PBIO): string; overload;
begin
  Result := BIO_to_string(b, TEncoding.ANSI);
end;

function BN_num_bytes(a: PBIGNUM): Integer;
begin
  Result := (BN_num_bits(a)+7) div 8;
end;

function X509_get_notBefore(x509: PX509):PASN1_TIME; {$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Assert(x509<>nil);
  Result := X509_get0_notBefore(x509);
end;

function X509_get_notAfter(x509: PX509):PASN1_TIME; {$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Assert(x509<>nil);
  Result := X509_get0_notAfter(x509);
end;

function BIO_pending(b : PBIO) : TIdC_INT; {$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := BIO_ctrl(b,BIO_CTRL_PENDING_const,0,nil);
end;

{$ENDIF}

function EVP_DecryptUpdate(ctx: PEVP_CIPHER_CTX; data_out: PByte; var outl: integer; data_in: PByte; inl: integer): integer; {$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  {$IFNDEF USE_TAURUS_TLS}
  // Use the OpenSSL.libeay32 binding: its prototype correctly declares "outl" as
  // "var" (a pointer), unlike the Indy header shipped with some Delphi versions.
  Result := OpenSSL.libeay32.EVP_DecryptUpdate(ctx, data_out, outl, data_in, inl);
  {$ELSE}
  Result := TaurusTLSHeaders_evp.EVP_DecryptUpdate(ctx, data_out[0], outl, data_in^, inl);
  {$ENDIF}
end;

function EVP_DecryptFinal(ctx: PEVP_CIPHER_CTX; data_out: PByte; var outl: integer): integer; {$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  {$IFNDEF USE_TAURUS_TLS}
  Result := OpenSSL.libeay32.EVP_DecryptFinal(ctx, data_out, outl);
  {$ELSE}
  Result := TaurusTLSHeaders_evp.EVP_DecryptFinal(ctx, data_out, outl);
  {$ENDIF}
end;

function EVP_DecryptFinal_ex(ctx : PEVP_CIPHER_CTX; outm: PByte; var outl : integer) : integer; {$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  {$IFNDEF USE_TAURUS_TLS}
  Result := OpenSSL.libeay32.EVP_DecryptFinal_ex(ctx, outm, outl);
  {$ELSE}
  Result := TaurusTLSHeaders_evp.EVP_DecryptFinal_ex(PEVP_MD_CTX(ctx), outm^, outl);
  {$ENDIF}
end;

function EVP_EncryptUpdate(ctx : PEVP_CIPHER_CTX; _out : PByte; var outl : integer; _in : PByte; inl : integer): integer; {$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  {$IFNDEF USE_TAURUS_TLS}
  Result := OpenSSL.libeay32.EVP_EncryptUpdate(ctx, _out, outl, _in, inl);
  {$ELSE}
  Result := TaurusTLSHeaders_evp.EVP_EncryptUpdate(ctx, _out[0], outl, _in^, inl);
  {$ENDIF}
end;

function EVP_EncryptFinal_ex(ctx : PEVP_CIPHER_CTX; _out : PByte; var outl : integer) : integer; {$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  {$IFNDEF USE_TAURUS_TLS}
  Result := OpenSSL.libeay32.EVP_EncryptFinal_ex(ctx, _out, outl);
  {$ELSE}
  Result := TaurusTLSHeaders_evp.EVP_EncryptFinal_ex(ctx, _out[0], outl);
  {$ENDIF}
end;

function EVP_EncryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): integer;
begin
  {$IFNDEF USE_TAURUS_TLS}
  Result := IdSSLOpenSSLHeaders.EVP_EncryptInit_ex(ctx, cipher, impl, PAnsiChar(key), PAnsiChar(iv));
  {$ELSE}
  Result := TaurusTLSHeaders_evp.EVP_EncryptInit_ex(ctx, cipher, impl, key, iv);
  {$ENDIF}
end;

function EVP_DecryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): integer;
begin
  {$IFNDEF USE_TAURUS_TLS}
  Result := IdSSLOpenSSLHeaders.EVP_DecryptInit_ex(ctx, cipher, impl, PAnsiChar(key), PAnsiChar(iv));
  {$ELSE}
  Result := TaurusTLSHeaders_evp.EVP_DecryptInit_ex(ctx, cipher, impl, key, iv);
  {$ENDIF}
end;

function BIO_get_mem_data(b : PBIO; pp : Pointer) : Integer; {$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := BIO_ctrl(b,BIO_CTRL_INFO,0,pp);
end;

function BIO_new_mem_buf(InputBuffer :TBytes): PBIO;
begin
  {$IFNDEF USE_TAURUS_TLS}
  Result := IdSSLOpenSSLHeaders.BIO_new_mem_buf(InputBuffer, Length(InputBuffer));
  {$ELSE}
  Result := TaurusTLSHeaders_bio.BIO_new_mem_buf(InputBuffer[0], Length(InputBuffer));
  {$ENDIF}
end;

function BIO_read(b: PBIO; var OutputBuffer :TBytes): Integer;
begin
  {$IFNDEF USE_TAURUS_TLS}
  Result := IdSSLOpenSSLHeaders.BIO_read(b, @OutputBuffer[0], Length(OutputBuffer));
  {$ELSE}
  Result := TaurusTLSHeaders_bio.BIO_read(b, OutputBuffer[0], Length(OutputBuffer));
  {$ENDIF}
end;

function BIO_write(b: PBIO; InputBuffer :TBytes): Integer;
begin
  {$IFNDEF USE_TAURUS_TLS}
  Result := IdSSLOpenSSLHeaders.BIO_write(b, InputBuffer, Length(InputBuffer));
  {$ELSE}
  Result := TaurusTLSHeaders_bio.BIO_write(b, InputBuffer[0], Length(InputBuffer));
  {$ENDIF}
end;

function Base64Encode(InputBuffer :TBytes) :TBytes;
var
  bio, b64 :PBIO;
  bdata :Pointer;
  datalen :Integer;
begin
  b64 := BIO_new(BIO_f_base64());
  bio := BIO_new(BIO_s_mem());
  BIO_push(b64, bio);

  BIO_write(b64, InputBuffer);
  BIO_flush(b64);

  bdata := nil;
  datalen :=  BIO_get_mem_data(bio, @bdata);
  SetLength(Result, datalen);
  Move(bdata^, Result[0], datalen);

  BIO_free_all(b64);
end;

function Base64Decode(InputBuffer :TBytes) :TBytes;
var
  bio, b64 :PBIO;
  datalen :Integer;
begin
  b64 := BIO_new(BIO_f_base64());
  bio := BIO_new_mem_buf(InputBuffer);
  try
    BIO_push(b64, bio);

    SetLength(Result, Length(InputBuffer));
    datalen := BIO_read(b64, Result);
    if datalen < 0 then
      RaiseOpenSSLError('Base64 error');

    SetLength(Result, datalen);
    BIO_flush(b64);
  finally
    BIO_free_all(b64);
  end;
end;

function EVP_GetSalt: TBytes;
begin
  SetLength(result, PKCS5_SALT_LEN);
  {$IFNDEF USE_TAURUS_TLS}
  RAND_pseudo_bytes(@result[0], PKCS5_SALT_LEN);
  {$ELSE}
  RAND_bytes(@result[0], PKCS5_SALT_LEN);
  {$ENDIF}
end;

procedure EVP_GetKeyIV(APassword: TBytes; ACipher: PEVP_CIPHER; const ASalt: TBytes; out Key, IV: TBytes);
var
  IVLen, KeyLen: Integer;
begin
  {$IFDEF USE_TAURUS_TLS}
  KeyLen := EVP_CIPHER_key_length(ACipher);
  IVLen  := EVP_CIPHER_iv_length(ACipher);
  {$ELSE}
  KeyLen := ACipher^.key_len;
  IVLen  := ACipher^.iv_len;
  {$ENDIF}
  SetLength(Key, KeyLen);
  SetLength(IV, IVLen);
  if IVLen > 0 then
    EVP_BytesToKey(ACipher, EVP_md5, @ASalt[0], @APassword[0], Length(APassword), 1, @Key[0], @IV[0])
  else
    EVP_BytesToKey(ACipher, EVP_md5, @ASalt[0], @APassword[0], Length(APassword), 1, @Key[0], nil);
end;

procedure EVP_GetKeyIV(APassword: string; ACipher: PEVP_CIPHER; const ASalt: TBytes; out Key, IV: TBytes);
begin
  EVP_GetKeyIV(TEncoding.UTF8.GetBytes(APassword), ACipher, ASalt, Key, IV);
end;

function GetOpenSSLErrorMessage: string;
var
  ErrMsg: PAnsiChar;
begin
  ErrMsg := ERR_error_string(ERR_get_error, nil);
  Result := string(AnsiString(ErrMsg));
end;

procedure RaiseOpenSSLError(const AMessage :string);
var
  ErrCode: Integer;
  ErrMsg, FullMsg: string;
begin
  ErrCode := ERR_get_error;
  ErrMsg := string(AnsiString(ERR_error_string(ErrCode, nil)));
  if AMessage = '' then
    FullMsg := ErrMsg
  else
    FullMsg := AMessage + ': ' + ErrMsg;
  raise EOpenSSLLibError.Create(ErrCode, FullMsg);
end;

{ TOpenSLLBase }

constructor TOpenSLLBase.Create;
begin
  inherited;
  CheckOpenSSLLibrary;
end;

class procedure TOpenSLLBase.CheckOpenSSLLibrary;
begin
  {$IFNDEF USE_TAURUS_TLS}
  if not LoadOpenSSLLibraryEx then
    raise EOpenSSLError.Create('Cannot open "OpenSSL" library');
  {$ELSE}
  if not GetOpenSSLLoader.Load then
    raise EOpenSSLError.Create('Cannot open "OpenSSL" library');
  {$ENDIF}
end;

{ EOpenSSLLibError }

constructor EOpenSSLLibError.Create(Code: Integer; const Msg: string);
begin
  FErrorCode := Code;
  inherited Create(Msg);
end;

{ TSubjectInfo }

class operator TSubjectInfo.Implicit(const Value: string): TSubjectInfo;
begin
  Result := TSubjectInfo.Create(Value, '/');
end;

constructor TSubjectInfo.Create(const Value: string; Delimiter: Char);
var
  StringList: TStringList;
begin
  StringList := TStringList.Create;
  try
    StringList.StrictDelimiter := True;
    StringList.NameValueSeparator := '=';
    StringList.Delimiter := Delimiter;
    StringList.DelimitedText := Value;

    // Remove the first empty element
    if (StringList.Count > 0) and (StringList[0] = '') then
      StringList.Delete(0);

    FCommonName := StringList.Values['CN'];
    FOrganization := StringList.Values['O'];
    FOrganizationalUnit := StringList.Values['OU'];
    FCountry := StringList.Values['C'];
    FState := StringList.Values['ST'];
    FLocality := StringList.Values['L'];
    FEmailAddress := StringList.Values['EMAIL'];
    if FEmailAddress = '' then
      FEmailAddress := StringList.Values['EMAILADDRESS'];

  finally
    StringList.Free;
  end;
end;

class operator TSubjectInfo.Implicit(const Value: TSubjectInfo): string;
var
  StringList: TStringList;
begin
  StringList := TStringList.Create;
  try
    StringList.StrictDelimiter := True;
    StringList.NameValueSeparator := '=';
    StringList.Delimiter := '/';

    StringList.Values['CN'] := Value.FCommonName;
    StringList.Values['O'] := Value.FOrganization;
    StringList.Values['OU'] := Value.FOrganizationalUnit;
    StringList.Values['C'] := Value.FCountry;
    StringList.Values['ST'] := Value.FState;
    StringList.Values['L'] := Value.FLocality;
    StringList.Values['emailAddress'] := Value.FEmailAddress;

    Result := StringList.DelimitedText;

  finally
    StringList.Free;
  end;
end;

{ TSerialNumber }

class operator TSerialNumber.Implicit(const Value: TSerialNumber): string;
begin
  Result := Value.ToHexString();
end;

class operator TSerialNumber.Implicit(const Value: string): TSerialNumber;
var
  CleanHex: string;
  i: Integer;
  ByteCount: Integer;
  ByteVal: Byte;
begin
  // Remove all separators (: - space)
  CleanHex := '';
  for i := 1 to Length(Value) do
  begin
    if CharInSet(Value[i], ['0'..'9', 'A'..'F', 'a'..'f']) then
      CleanHex := CleanHex + Value[i];
  end;

  // Convert hex string to bytes
  if CleanHex = '' then
  begin
    SetLength(Result.FData, 0);
    Exit;
  end;

  ByteCount := (Length(CleanHex) + 1) div 2;
  SetLength(Result.FData, ByteCount);

  for i := 0 to ByteCount - 1 do
  begin
    if i * 2 + 2 <= Length(CleanHex) then
      ByteVal := StrToInt('$' + Copy(CleanHex, i * 2 + 1, 2))
    else
      ByteVal := StrToInt('$' + Copy(CleanHex, i * 2 + 1, 1));
    Result.FData[i] := ByteVal;
  end;
end;

class operator TSerialNumber.Implicit(const Value: TSerialNumber): Int64;
begin
  Result := Value.ToInt64;
end;

class operator TSerialNumber.Implicit(const Value: Int64): TSerialNumber;
var
  i: Integer;
  TempValue: Int64;
  ByteList: TArray<Byte>;
begin
  if Value = 0 then
  begin
    SetLength(Result.FData, 1);
    Result.FData[0] := 0;
    Exit;
  end;

  // Convert Int64 to bytes (big-endian)
  SetLength(ByteList, 0);
  TempValue := Value;

  while TempValue > 0 do
  begin
    SetLength(ByteList, Length(ByteList) + 1);
    ByteList[High(ByteList)] := Byte(TempValue and $FF);
    TempValue := TempValue shr 8;
  end;

  // Reverse to big-endian
  SetLength(Result.FData, Length(ByteList));
  for i := 0 to High(ByteList) do
    Result.FData[i] := ByteList[High(ByteList) - i];
end;

function TSerialNumber.ToHexString(Separator: Char): string;
var
  i: Integer;
  HexParts: TArray<string>;
begin
  if Length(FData) = 0 then
  begin
    Result := '';
    Exit;
  end;

  SetLength(HexParts, Length(FData));
  for i := 0 to High(FData) do
    HexParts[i] := IntToHex(FData[i], 2);

  if Separator = #0 then
    Result := string.Join('', HexParts)
  else
    Result := string.Join(Separator, HexParts);
end;

function TSerialNumber.ToInt64: Int64;
begin
  if not TryToInt64(Result) then
    raise EConvertError.Create('Serial number too large to convert to Int64');
end;

function TSerialNumber.TryToInt64(out Value: Int64): Boolean;
var
  i: Integer;
begin
  Value := 0;
  //Result := False;

  // Empty serial number
  if Length(FData) = 0 then
    Exit(True);

  // Check if it fits in Int64 (max 8 bytes, and MSB must not indicate negative)
  if Length(FData) > 8 then
    Exit(False);

  if (Length(FData) = 8) and (FData[0] and $80 <> 0) then
    Exit(False); // Would be negative

  // Convert big-endian bytes to Int64
  for i := 0 to High(FData) do
  begin
    Value := (Value shl 8) or FData[i];
  end;

  Result := True;
end;

function TSerialNumber.IsEmpty: Boolean;
begin
  Result := Length(FData) = 0;
end;

class operator TSerialNumber.Implicit(const Value: TBytes): TSerialNumber;
begin
  Result.FData := Value;
end;

end.
