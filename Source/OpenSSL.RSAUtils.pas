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
unit OpenSSL.RSAUtils;

interface

uses
  System.Classes, System.SysUtils, System.AnsiStrings, OpenSSL.libeay32,
  OpenSSL.Core, IdSSLOpenSSLHeaders;

type
  TX509Cerificate = class;

  TPassphraseEvent = procedure (Sender :TObject; var Passphrase :string) of object;

  TPublicKeyFormat = (kfDefault, kfRSAPublicKey);
  TPrivateKeyFormat = (kpDefault, kpRSAPrivateKey);

  // RSA public key
  TCustomRSAPublicKey = class(TOpenSLLBase)
  private
    FBuffer: TBytes;
    FCerificate :TX509Cerificate;
  protected
    function GetRSA :PRSA; virtual; abstract;
    procedure FreeRSA; virtual; abstract;
  public
    constructor Create; override;
    destructor Destroy; override;
    function Print: string;
    function IsValid :Boolean;
    procedure LoadFromFile(const FileName :string; AFormat: TPublicKeyFormat = kfDefault); virtual;
    procedure LoadFromStream(AStream :TStream; AFormat: TPublicKeyFormat = kfDefault); virtual;
    procedure LoadFromCertificate(Cerificate :TX509Cerificate);
    procedure SaveToFile(const FileName :string; AFormat: TPublicKeyFormat = kfDefault); virtual;
    procedure SaveToStream(AStream :TStream; AFormat: TPublicKeyFormat = kfDefault); virtual;
  end;

  TRSAPublicKey = class(TCustomRSAPublicKey)
  private
    FRSA :PRSA;
  protected
    procedure FreeRSA; override;
    function GetRSA :PRSA; override;
  public
    constructor Create; override;
    procedure LoadFromStream(AStream :TStream; AFormat: TPublicKeyFormat = kfDefault); override;
  end;

  // RSA private key
  TCustomRSAPrivateKey = class(TOpenSLLBase)
  private
    FBuffer: TBytes;
    FOnNeedPassphrase: TPassphraseEvent;
  protected
    function GetRSA :PRSA; virtual; abstract;
    procedure FreeRSA; virtual; abstract;
  public
    constructor Create; override;
    destructor Destroy; override;
    function IsValid :Boolean;
    function Print: string;
    procedure LoadFromFile(const FileName :string; AFormat: TPrivateKeyFormat = kpDefault); virtual;
    procedure LoadFromStream(AStream :TStream; AFormat: TPrivateKeyFormat = kpDefault); virtual;
    procedure SaveToFile(const FileName :string; AFormat: TPrivateKeyFormat = kpDefault); virtual;
    procedure SaveToStream(AStream :TStream; AFormat: TPrivateKeyFormat = kpDefault); virtual;
    property OnNeedPassphrase :TPassphraseEvent read FOnNeedPassphrase write FOnNeedPassphrase;
  end;

  TRSAPrivateKey = class(TCustomRSAPrivateKey)
  private
    FRSA :PRSA;
  protected
    procedure FreeRSA; override;
    function GetRSA :PRSA; override;
  public
    constructor Create; override;
    procedure LoadFromStream(AStream :TStream; AFormat: TPrivateKeyFormat = kpDefault); override;
  end;

  // certificate containing an RSA public key
  TX509Cerificate = class(TOpenSLLBase)
  private
    FBuffer: TBytes;
    FPublicRSA :PRSA;
    FX509 :pX509;
    procedure FreeRSA;
    procedure FreeX509;
    function GetPublicRSA :PRSA;
  public
    constructor Create; override;
    destructor Destroy; override;

    function IsValid :Boolean;
    function Print: string;
    procedure LoadFromFile(const FileName :string);
    procedure LoadFromStream(AStream :TStream);
  end;

  TRSAKeyPair = class(TOpenSLLBase)
  private
    FRSA: PRSA;
    FPrivateKey: TCustomRSAPrivateKey;
    FPublicKey: TCustomRSAPublicKey;
    procedure FreeRSA;
  public
    property PrivateKey: TCustomRSAPrivateKey read FPrivateKey;
    property PublicKey: TCustomRSAPublicKey read FPublicKey;

    procedure GenerateKey; overload;
    procedure GenerateKey(KeySize: Integer); overload;
    constructor Create; override;
    destructor Destroy; override;
  end;

  TRSAUtil = class(TOpenSLLBase)
  private
    FPublicKey :TCustomRSAPublicKey;
    FPrivateKey: TCustomRSAPrivateKey;
    FOwnedPrivateKey: TCustomRSAPrivateKey;
    FOwnedPublicKey: TCustomRSAPublicKey;
    procedure SetPrivateKey(const Value: TCustomRSAPrivateKey);
    procedure SetPublicKey(const Value: TCustomRSAPublicKey);
  public
    constructor Create; override;
    destructor Destroy; override;
    procedure PublicEncrypt(InputStream :TStream; OutputStream :TStream; Padding :TRASPadding = rpPKCS); overload;
    procedure PublicEncrypt(const InputFileName, OutputFileName :TFileName; Padding :TRASPadding = rpPKCS); overload;
    procedure PrivateDecrypt(InputStream :TStream; OutputStream :TStream; Padding :TRASPadding = rpPKCS); overload;
    procedure PrivateDecrypt(const InputFileName, OutputFileName :TFileName; Padding :TRASPadding = rpPKCS); overload;

    property PublicKey :TCustomRSAPublicKey read FPublicKey write SetPublicKey;
    property PrivateKey :TCustomRSAPrivateKey read FPrivateKey write SetPrivateKey;
  end;

implementation

type
  TRSAKeyPairPrivateKey = class(TCustomRSAPrivateKey)
  private
    FKeyPair: TRSAKeyPair;
  protected
    procedure FreeRSA; override;
    function GetRSA :PRSA; override;
  public
    constructor Create(KeyPair: TRSAKeyPair); reintroduce;
  end;

  TRSAKeyPairPublicKey = class(TCustomRSAPublicKey)
  private
    FKeyPair: TRSAKeyPair;
  protected
    procedure FreeRSA; override;
    function GetRSA :PRSA; override;
  public
    constructor Create(KeyPair: TRSAKeyPair); reintroduce;
  end;

const
  PaddingMap : array [TRASPadding] of Integer = (RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_SSLV23_PADDING, RSA_NO_PADDING);

// rwflag is a flag set to 0 when reading and 1 when writing
// The u parameter has the same value as the u parameter passed to the PEM routines
function ReadKeyCallback(buf: PAnsiChar; buffsize: integer; rwflag: integer; u: pointer): integer; cdecl;
var
  Len :Integer;
  Password :string;
  PrivateKey :TCustomRSAPrivateKey;
begin
  Result := 0;
  if Assigned(u) then
  begin
    PrivateKey := TCustomRSAPrivateKey(u);
    if Assigned(PrivateKey.FOnNeedPassphrase) then
    begin
      PrivateKey.FOnNeedPassphrase(PrivateKey, Password);
      if Length(Password) < buffsize then
        Len := Length(Password)
      else
        Len := buffsize;
      System.AnsiStrings.StrPLCopy(buf, AnsiString(Password), Len);
      Result := Len;
    end;
  end;
end;


procedure TRSAUtil.PublicEncrypt(InputStream, OutputStream: TStream; Padding: TRASPadding);
var
  InputBuffer :TBytes;
  OutputBuffer :TBytes;
  RSAOutLen :Integer;
begin
  if not PublicKey.IsValid then
    raise Exception.Create('Public key not assigned');

  SetLength(InputBuffer, InputStream.Size);
  InputStream.ReadBuffer(InputBuffer[0], InputStream.Size);

  RSAOutLen := RSA_size(FPublicKey.GetRSA);
  SetLength(OutputBuffer, RSAOutLen);

  RSAOutLen := RSA_public_encrypt(Length(InputBuffer), PByte(InputBuffer), PByte(OutputBuffer), FPublicKey.GetRSA, PaddingMap[Padding]);

  if RSAOutLen <= 0 then
    RaiseOpenSSLError('RSA operation error');

  OutputStream.Write(OutputBuffer[0], RSAOutLen);
end;

constructor TRSAUtil.Create;
begin
  inherited;
  FOwnedPublicKey := TRSAPublicKey.Create;
  FOwnedPrivateKey := TRSAPrivateKey.Create;

  FPrivateKey := FOwnedPrivateKey;
  FPublicKey := FOwnedPublicKey;
end;

destructor TRSAUtil.Destroy;
begin
  FOwnedPublicKey.Free;
  FOwnedPrivateKey.Free;
  inherited;
end;

procedure TRSAUtil.PrivateDecrypt(InputStream, OutputStream: TStream;
  Padding: TRASPadding);
var
  InputBuffer :TBytes;
  OutputBuffer :TBytes;
  RSAOutLen :Integer;
begin
  if not PrivateKey.IsValid then
    raise Exception.Create('Private key not assigned');

  SetLength(InputBuffer, InputStream.Size);
  InputStream.ReadBuffer(InputBuffer[0], InputStream.Size);

  RSAOutLen := RSA_size(FPrivateKey.GetRSA);
  SetLength(OutputBuffer, RSAOutLen);

  RSAOutLen := RSA_private_decrypt(Length(InputBuffer), PByte(InputBuffer), PByte(OutputBuffer), FPrivateKey.GetRSA, PaddingMap[Padding]);

  if RSAOutLen <= 0 then
    RaiseOpenSSLError('RSA operation error');

  OutputStream.Write(OutputBuffer[0], RSAOutLen);
end;

procedure TRSAUtil.PrivateDecrypt(const InputFileName,
  OutputFileName: TFileName; Padding: TRASPadding);
var
  InputFile, OutputFile :TStream;
begin
  InputFile := TFileStream.Create(InputFileName, fmOpenRead);
  try
    OutputFile := TFileStream.Create(OutputFileName, fmCreate);
    try
      PrivateDecrypt(InputFile, OutputFile, Padding);
    finally
      OutputFile.Free;
    end;
  finally
    InputFile.Free;
  end;
end;

procedure TRSAUtil.PublicEncrypt(const InputFileName, OutputFileName: TFileName;
  Padding: TRASPadding);
var
  InputFile, OutputFile :TStream;
begin
  InputFile := TFileStream.Create(InputFileName, fmOpenRead);
  try
    OutputFile := TFileStream.Create(OutputFileName, fmCreate);
    try
      PublicEncrypt(InputFile, OutputFile, Padding);
    finally
      OutputFile.Free;
    end;
  finally
    InputFile.Free;
  end;
end;

procedure TRSAUtil.SetPrivateKey(const Value: TCustomRSAPrivateKey);
begin
  FPrivateKey := Value;
end;

procedure TRSAUtil.SetPublicKey(const Value: TCustomRSAPublicKey);
begin
  FPublicKey := Value;
end;

{ TX509Cerificate }

constructor TX509Cerificate.Create;
begin
  inherited;
  FPublicRSA := nil;
end;

destructor TX509Cerificate.Destroy;
begin
  FreeRSA;
  FreeX509;
  inherited;
end;

procedure TX509Cerificate.FreeRSA;
begin
  if FPublicRSA <> nil then
  begin
    RSA_free(FPublicRSA);
    FPublicRSA := nil;
  end;
end;

procedure TX509Cerificate.FreeX509;
begin
  if FX509 <> nil then
    X509_free(FX509);
end;

function TX509Cerificate.GetPublicRSA: PRSA;
var
  Key: pEVP_PKEY;
begin
  if not Assigned(FPublicRSA) then
  begin
    Key := X509_get_pubkey(FX509);
    try
      FPublicRSA := EVP_PKEY_get1_RSA(Key);
      if not Assigned(FPublicRSA) then
        RaiseOpenSSLError('X501 unable to read public key');
    finally
      EVP_PKEY_free(Key);
    end;
  end;

  Result := FPublicRSA;
end;

function TX509Cerificate.IsValid: Boolean;
begin
  Result := Assigned(FX509);
end;

function TX509Cerificate.Print: string;
var
  bp: PBIO;
begin
  bp := BIO_new(BIO_s_mem());
  try
    if RSA_print(bp, GetPublicRSA, 0) = 0 then
      RaiseOpenSSLError('RSA_print');
    Result := BIO_to_string(bp);
  finally
    BIO_free(bp);
  end;
end;

procedure TX509Cerificate.LoadFromFile(const FileName: string);
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    LoadFromStream(Stream);
  finally
    Stream.Free;
  end;
end;

procedure TX509Cerificate.LoadFromStream(AStream: TStream);
var
  KeyFile :pBIO;
begin
  FreeRSA;
  FreeX509;

  SetLength(FBuffer, AStream.Size);
  AStream.ReadBuffer(FBuffer[0], AStream.Size);
  KeyFile := BIO_new_mem_buf(FBuffer, Length(FBuffer));
  if KeyFile = nil then
    RaiseOpenSSLError('X509 load stream error');
  try
    FX509 := PEM_read_bio_X509(KeyFile, nil, nil, nil);
    if not Assigned(FX509) then
      RaiseOpenSSLError('X509 load certificate error');
  finally
    BIO_free(KeyFile);
  end;
end;

{ TCustomRSAPrivateKey }

constructor TCustomRSAPrivateKey.Create;
begin
  inherited;
end;

destructor TCustomRSAPrivateKey.Destroy;
begin
  FreeRSA;
  inherited;
end;

function TCustomRSAPrivateKey.IsValid: Boolean;
begin
  Result := GetRSA <> nil;
end;

procedure TCustomRSAPrivateKey.LoadFromFile(const FileName: string; AFormat: TPrivateKeyFormat = kpDefault);
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    LoadFromStream(Stream, AFormat);
  finally
    Stream.Free;
  end;
end;

procedure TCustomRSAPrivateKey.LoadFromStream(AStream: TStream; AFormat: TPrivateKeyFormat = kpDefault);
begin
  raise EOpenSSLError.Create('Cannot load private key');
end;

function TCustomRSAPrivateKey.Print: string;
var
  bp: PBIO;
begin
  bp := BIO_new(BIO_s_mem());
  try
    if RSA_print(bp, GetRSA, 0) = 0 then
      RaiseOpenSSLError('RSA_print');
    Result := BIO_to_string(bp);
  finally
    BIO_free(bp);
  end;
end;

procedure TCustomRSAPrivateKey.SaveToFile(const FileName: string;
  AFormat: TPrivateKeyFormat);
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(FileName, fmCreate or fmShareDenyWrite);
  try
    SaveToStream(Stream, AFormat);
  finally
    Stream.Free;
  end;
end;

procedure TCustomRSAPrivateKey.SaveToStream(AStream: TStream;
  AFormat: TPrivateKeyFormat);
var
  PrivateKey: PBIO;
  KeyLength: Integer;
  Buffer: TBytes;
  pKey: pEVP_PKEY;
begin
  PrivateKey := BIO_new(BIO_s_mem);
  try
    case AFormat of
      kpDefault: begin
        pKey := EVP_PKEY_new(); // TODO: check value
        try
          EVP_PKEY_set1_RSA(pKey, GetRSA); // TODO: check value
          PEM_write_bio_PrivateKey(PrivateKey, pKey, nil, nil, 0, nil, nil);
          KeyLength := BIO_pending(PrivateKey);
        finally
          EVP_PKEY_free(pKey);
        end;
      end;
      kpRSAPrivateKey: begin
        PEM_write_bio_RSAPrivateKey(PrivateKey, GetRSA, nil, nil, 0, nil, nil);
        KeyLength := BIO_pending(PrivateKey);
      end;
      else
        raise EOpenSSLError.Create('Invalid format');
    end;

    SetLength(Buffer, KeyLength);
    BIO_read(PrivateKey, @Buffer[0], KeyLength);
  finally
    BIO_free(PrivateKey);
  end;
  AStream.Write(Buffer[0], Length(Buffer));
end;

{ TCustomRSAPublicKey }

constructor TCustomRSAPublicKey.Create;
begin
  inherited;
end;

destructor TCustomRSAPublicKey.Destroy;
begin
  FreeRSA;
  inherited;
end;

function TCustomRSAPublicKey.IsValid: Boolean;
begin
  Result := GetRSA <> nil;
end;

procedure TCustomRSAPublicKey.LoadFromCertificate(Cerificate: TX509Cerificate);
begin
  FCerificate := Cerificate;
end;

procedure TCustomRSAPublicKey.LoadFromFile(const FileName: string; AFormat: TPublicKeyFormat = kfDefault);
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    LoadFromStream(Stream, AFormat);
  finally
    Stream.Free;
  end;
end;

procedure TCustomRSAPublicKey.LoadFromStream(AStream: TStream; AFormat: TPublicKeyFormat);
begin
  raise EOpenSSLError.Create('Cannot load private key');
end;

function TCustomRSAPublicKey.Print: string;
var
  bp: PBIO;
begin
  bp := BIO_new(BIO_s_mem());
  try
    if RSA_print(bp, GetRSA, 0) = 0 then
      RaiseOpenSSLError('RSA_print');
    Result := BIO_to_string(bp);
  finally
    BIO_free(bp);
  end;
end;

procedure TCustomRSAPublicKey.SaveToFile(const FileName: string;
  AFormat: TPublicKeyFormat);
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(FileName, fmCreate or fmShareDenyWrite);
  try
    SaveToStream(Stream, AFormat);
  finally
    Stream.Free;
  end;
end;

procedure TCustomRSAPublicKey.SaveToStream(AStream: TStream;
  AFormat: TPublicKeyFormat);
var
  PublicKey: PBIO;
  KeyLength: Integer;
  Buffer: TBytes;
  pKey: pEVP_PKEY;
begin
  PublicKey := BIO_new(BIO_s_mem);
  try

    case AFormat of
      kfDefault: begin
        pKey := EVP_PKEY_new(); // TODO: check value
        try
          EVP_PKEY_set1_RSA(pKey, GetRSA); // TODO: check value
          PEM_write_bio_PUBKEY(PublicKey, pKey);
          KeyLength := BIO_pending(PublicKey);
        finally
          EVP_PKEY_free(pKey);
        end;
      end;
      kfRSAPublicKey: begin
        PEM_write_bio_RSAPublicKey(PublicKey, GetRSA);
        KeyLength := BIO_pending(PublicKey);
      end;
      else
        raise EOpenSSLError.Create('Invalid format');
    end;

    SetLength(Buffer, KeyLength);
    BIO_read(PublicKey, @Buffer[0], KeyLength);
  finally
    BIO_free(PublicKey);
  end;
  AStream.WriteBuffer(Buffer[0], Length(Buffer));
end;

{ TRSAKeyPair }

constructor TRSAKeyPair.Create;
begin
  inherited;
  FPrivateKey := TRSAKeyPairPrivateKey.Create(Self);
  FPublicKey := TRSAKeyPairPublicKey.Create(Self);
end;

destructor TRSAKeyPair.Destroy;
begin
  FreeRSA;
  FPrivateKey.Free;
  FPublicKey.Free;
  inherited;
end;

procedure TRSAKeyPair.FreeRSA;
begin
  if FRSA <> nil then
  begin
    RSA_free(FRSA);
    FRSA := nil;
  end;
end;

// Thanks for Allen Drennan
// https://stackoverflow.com/questions/55229772/using-openssl-to-generate-keypairs/55239810#55239810
procedure TRSAKeyPair.GenerateKey(KeySize: Integer);
var
  Bignum: PBIGNUM;
begin
  FreeRSA;

  Bignum := BN_new();
  try
    if BN_set_word(Bignum, RSA_F4) = 1 then
    begin
      FRSA := RSA_new;
      try
        if BN_set_word(Bignum, RSA_F4) = 0 then
          RaiseOpenSSLError('BN_set_word');

        if RSA_generate_key_ex(FRSA, KeySize, Bignum, nil) = 0 then
          RaiseOpenSSLError('RSA_generate_key_ex');
      except
        FreeRSA;
        raise;
      end;
    end;
  finally
    BN_free(Bignum);
  end;
end;

procedure TRSAKeyPair.GenerateKey;
const
  DefaultKeySize = 2048;
begin
  GenerateKey(DefaultKeySize);
end;

{ TRSAPrivateKey }

constructor TRSAPrivateKey.Create;
begin
  inherited;
  FRSA := nil;
end;

procedure TRSAPrivateKey.FreeRSA;
begin
  if FRSA <> nil then
  begin
    RSA_free(FRSA);
    FRSA := nil;
  end;
end;

function TRSAPrivateKey.GetRSA: PRSA;
begin
  Result := FRSA;
end;

procedure TRSAPrivateKey.LoadFromStream(AStream: TStream; AFormat: TPrivateKeyFormat = kpDefault);
var
  KeyBuffer :pBIO;
  cb : ppem_password_cb;
  pKey : PEVP_PKEY;
begin
  cb := nil;
  if Assigned(FOnNeedPassphrase) then
    cb := @ReadKeyCallback;

  SetLength(FBuffer, AStream.Size);
  AStream.ReadBuffer(FBuffer[0], AStream.Size);
  KeyBuffer := BIO_new_mem_buf(FBuffer, Length(FBuffer));
  if KeyBuffer = nil then
    RaiseOpenSSLError('RSA load stream error');
  try

    case AFormat of
      kpDefault: begin

        pKey := PEM_read_bio_PrivateKey(KeyBuffer, nil, cb, nil);
        if not Assigned(pKey) then
          RaiseOpenSSLError('PUBKEY load public key error');

        try
          FRSA := EVP_PKEY_get1_RSA(pKey);

          if not Assigned(FRSA) then
            RaiseOpenSSLError('RSA load public key error');
        finally
          EVP_PKEY_free(pKey);
        end;
      end;
      kpRSAPrivateKey: begin
        FRSA := PEM_read_bio_RSAPrivateKey(KeyBuffer, nil, cb, nil);
        if not Assigned(FRSA) then
          RaiseOpenSSLError('RSA load private key error');
      end;
      else
        raise EOpenSSLError.Create('Invalid format');
    end;

  finally
    BIO_free(KeyBuffer);
  end;
end;

{ TRSAKeyPairPrivateKey }

constructor TRSAKeyPairPrivateKey.Create(KeyPair: TRSAKeyPair);
begin
  inherited Create;
  FKeyPair := KeyPair;
end;

procedure TRSAKeyPairPrivateKey.FreeRSA;
begin
end;

function TRSAKeyPairPrivateKey.GetRSA: PRSA;
begin
  Result := FKeyPair.FRSA;
end;

{ TRSAPublicKey }

constructor TRSAPublicKey.Create;
begin
  inherited;
  FRSA := nil;
end;

procedure TRSAPublicKey.FreeRSA;
begin
  if FRSA <> nil then
  begin
    RSA_free(FRSA);
    FRSA := nil;
  end;
end;

function TRSAPublicKey.GetRSA: PRSA;
begin
  if Assigned(FCerificate) then
    Result := FCerificate.GetPublicRSA
  else
    Result := FRSA;
end;

procedure TRSAPublicKey.LoadFromStream(AStream: TStream;
  AFormat: TPublicKeyFormat);
var
  KeyBuffer :pBIO;
  pKey :PEVP_PKEY;
begin
  SetLength(FBuffer, AStream.Size);
  AStream.ReadBuffer(FBuffer[0], AStream.Size);
  KeyBuffer := BIO_new_mem_buf(FBuffer, Length(FBuffer));
  if KeyBuffer = nil then
    RaiseOpenSSLError('RSA load stream error');
  try
    case AFormat of
      kfDefault: begin
        pKey := PEM_read_bio_PubKey(KeyBuffer, nil, nil, nil);
        if not Assigned(pKey) then
          RaiseOpenSSLError('PUBKEY load public key error');

        try
          FRSA := EVP_PKEY_get1_RSA(pKey);

          if not Assigned(FRSA) then
            RaiseOpenSSLError('RSA load public key error');
        finally
          EVP_PKEY_free(pKey);
        end;
      end;
      kfRSAPublicKey: begin
        FRSA := PEM_read_bio_RSAPublicKey(KeyBuffer, nil, nil, nil);
        if not Assigned(FRSA) then
          RaiseOpenSSLError('RSA load public key error');
      end;
      else
        raise EOpenSSLError.Create('Invalid format');
    end;
  finally
    BIO_free(KeyBuffer);
  end;
end;

{ TRSAKeyPairPublicKey }

constructor TRSAKeyPairPublicKey.Create(KeyPair: TRSAKeyPair);
begin
  inherited Create;
  FKeyPair := KeyPair;
end;

procedure TRSAKeyPairPublicKey.FreeRSA;
begin

end;

function TRSAKeyPairPublicKey.GetRSA: PRSA;
begin
  Result := FKeyPair.FRSA;
end;

end.
