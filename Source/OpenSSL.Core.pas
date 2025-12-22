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

uses
  System.Classes, System.SysUtils, System.StrUtils, IdSSLOpenSSLHeaders, OpenSSL.libeay32;

type
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

  EOpenSSLError = Exception;

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

implementation

function Base64Encode(InputBuffer :TBytes) :TBytes;
var
  bio, b64 :PBIO;
  bdata :Pointer;
  datalen :Integer;
begin
  b64 := BIO_new(BIO_f_base64());
  bio := BIO_new(BIO_s_mem());
  BIO_push(b64, bio);

  BIO_write(b64, @InputBuffer[0], Length(InputBuffer));
  BIO_flush(b64);

  bdata := nil;
  datalen :=  OpenSSL.libeay32.BIO_get_mem_data(bio, @bdata);
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
  bio := BIO_new_mem_buf(InputBuffer, Length(InputBuffer));
  try
    BIO_push(b64, bio);

    SetLength(Result, Length(InputBuffer));
    datalen := BIO_read(b64, @Result[0], Length(InputBuffer));
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
  RAND_pseudo_bytes(@result[0], PKCS5_SALT_LEN);
end;

procedure EVP_GetKeyIV(APassword: TBytes; ACipher: PEVP_CIPHER; const ASalt: TBytes; out Key, IV: TBytes);
begin
  SetLength(Key, EVP_MAX_KEY_LENGTH);
  SetLength(iv, EVP_MAX_IV_LENGTH);

  EVP_BytesToKey(ACipher,EVP_md5, @ASalt[0] ,@APassword[0]  , Length(APassword),1, @Key[0], @IV[0]);
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
  if not LoadOpenSSLLibraryEx then
    raise EOpenSSLError.Create('Cannot open "OpenSSL" library');
end;

{ EOpenSSLLibError }

constructor EOpenSSLLibError.Create(Code: Integer; const Msg: string);
begin
  FErrorCode := Code;
  inherited Create(Msg);
end;

{ TSubjectInfo }

class operator TSubjectInfo.Implicit(const Value: string): TSubjectInfo;
var
  StringList: TStringList;
begin
  StringList := TStringList.Create;
  try
    StringList.StrictDelimiter := True;
    StringList.NameValueSeparator := '=';
    StringList.Delimiter := '/';
    StringList.DelimitedText := Value;

    // Remove the first empty element
    if (StringList.Count > 0) and (StringList[0] = '') then
      StringList.Delete(0);

    Result.FCommonName := StringList.Values['CN'];
    Result.FOrganization := StringList.Values['O'];
    Result.FOrganizationalUnit := StringList.Values['OU'];
    Result.FCountry := StringList.Values['C'];
    Result.FState := StringList.Values['ST'];
    Result.FLocality := StringList.Values['L'];
    Result.FEmailAddress := StringList.Values['EMAIL'];
    if Result.FEmailAddress = '' then
      Result.FEmailAddress := StringList.Values['EMAILADDRESS'];

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
