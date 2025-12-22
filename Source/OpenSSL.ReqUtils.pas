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
unit OpenSSL.ReqUtils;

interface

uses
  System.Classes, System.SysUtils,
  OpenSSL.libeay32, OpenSSL.Core, OpenSSL.RSAUtils, IdSSLOpenSSLHeaders;

type
  TReqUtil = class(TOpenSLLBase)
  private
    FX509: pX509;
    FX509Req: pX509_REQ;
    FPrivateKey: TRSAPrivateKey;
    FKeyPair: TRSAKeyPair;

    procedure FreeX509;
    procedure FreeX509Req;
    procedure AddSubjectName(Name: pX509_NAME; const Subject: TSubjectInfo);
  public
    constructor Create; override;
    destructor Destroy; override;

    procedure GenerateSelfSignedCertificate(const Subject: TSubjectInfo;
      ValidDays: Integer = 365; KeySize: Integer = 2048);
    procedure GenerateCSR(const Subject: TSubjectInfo; KeySize: Integer = 2048);

    procedure SaveCertificateToFile(const FileName: string);
    procedure SaveCertificateToStream(AStream: TStream);
    procedure SaveCSRToFile(const FileName: string);
    procedure SaveCSRToStream(AStream: TStream);
    procedure SavePrivateKeyToFile(const FileName: string);
    procedure SavePrivateKeyToStream(AStream: TStream);
    procedure SavePublicKeyToFile(const FileName: string);
    procedure SavePublicKeyToStream(AStream: TStream);

    property PrivateKey: TRSAPrivateKey read FPrivateKey;
  end;

implementation

{ TReqUtil }

constructor TReqUtil.Create;
begin
  inherited;
  FX509 := nil;
  FX509Req := nil;
  FPrivateKey := nil;
  FKeyPair := nil;
end;

destructor TReqUtil.Destroy;
begin
  FreeX509;
  FreeX509Req;
  FPrivateKey.Free;
  FKeyPair.Free;
  inherited;
end;

procedure TReqUtil.FreeX509;
begin
  if FX509 <> nil then
  begin
    X509_free(FX509);
    FX509 := nil;
  end;
end;

procedure TReqUtil.FreeX509Req;
begin
  if FX509Req <> nil then
  begin
    X509_REQ_free(FX509Req);
    FX509Req := nil;
  end;
end;

procedure TReqUtil.AddSubjectName(Name: pX509_NAME; const Subject: TSubjectInfo);
begin
  // Add subject fields only if not empty
  // Order: C, ST, L, O, OU, CN, emailAddress

  if Subject.Country <> '' then
  begin
    if X509_NAME_add_entry_by_txt(Name, 'C', MBSTRING_ASC,
       PAnsiChar(AnsiString(Subject.Country)), -1, -1, 0) = 0 then
      RaiseOpenSSLError('Failed to add Country to subject');
  end;

  if Subject.State <> '' then
  begin
    if X509_NAME_add_entry_by_txt(Name, 'ST', MBSTRING_ASC,
       PAnsiChar(AnsiString(Subject.State)), -1, -1, 0) = 0 then
      RaiseOpenSSLError('Failed to add State to subject');
  end;

  if Subject.Locality <> '' then
  begin
    if X509_NAME_add_entry_by_txt(Name, 'L', MBSTRING_ASC,
       PAnsiChar(AnsiString(Subject.Locality)), -1, -1, 0) = 0 then
      RaiseOpenSSLError('Failed to add Locality to subject');
  end;

  if Subject.Organization <> '' then
  begin
    if X509_NAME_add_entry_by_txt(Name, 'O', MBSTRING_ASC,
       PAnsiChar(AnsiString(Subject.Organization)), -1, -1, 0) = 0 then
      RaiseOpenSSLError('Failed to add Organization to subject');
  end;

  if Subject.OrganizationalUnit <> '' then
  begin
    if X509_NAME_add_entry_by_txt(Name, 'OU', MBSTRING_ASC,
       PAnsiChar(AnsiString(Subject.OrganizationalUnit)), -1, -1, 0) = 0 then
      RaiseOpenSSLError('Failed to add OrganizationalUnit to subject');
  end;

  if Subject.CommonName <> '' then
  begin
    if X509_NAME_add_entry_by_txt(Name, 'CN', MBSTRING_ASC,
       PAnsiChar(AnsiString(Subject.CommonName)), -1, -1, 0) = 0 then
      RaiseOpenSSLError('Failed to add CommonName to subject');
  end;

  if Subject.EmailAddress <> '' then
  begin
    if X509_NAME_add_entry_by_txt(Name, 'emailAddress', MBSTRING_ASC,
       PAnsiChar(AnsiString(Subject.EmailAddress)), -1, -1, 0) = 0 then
      RaiseOpenSSLError('Failed to add EmailAddress to subject');
  end;
end;

procedure TReqUtil.GenerateSelfSignedCertificate(const Subject: TSubjectInfo;
  ValidDays: Integer; KeySize: Integer);
var
  pKey: pEVP_PKEY;
  SubjectName: pX509_NAME;
  TempStream: TMemoryStream;
begin
  FreeX509;
  FreeX509Req;

  // Free existing keys
  FPrivateKey.Free;
  FPrivateKey := nil;
  FKeyPair.Free;
  FKeyPair := nil;

  // Generate RSA key pair
  FKeyPair := TRSAKeyPair.Create;
  FKeyPair.GenerateKey(KeySize);

  // Copy private key to internal FPrivateKey via stream
  FPrivateKey := TRSAPrivateKey.Create;
  TempStream := TMemoryStream.Create;
  try
    FKeyPair.PrivateKey.SaveToStream(TempStream);
    TempStream.Position := 0;
    FPrivateKey.LoadFromStream(TempStream);
  finally
    TempStream.Free;
  end;

  // Create X509 structure
  FX509 := X509_new();
  if FX509 = nil then
    RaiseOpenSSLError('Failed to create X509 structure');

  try
    // Set version (X509v3 = 2)
    if X509_set_version(FX509, 2) = 0 then
      RaiseOpenSSLError('Failed to set X509 version');

    // Set serial number (using timestamp for uniqueness)
    if ASN1_INTEGER_set(X509_get_serialNumber(FX509), TThread.GetTickCount64) = 0 then
      RaiseOpenSSLError('Failed to set serial number');

    // Set validity period
    // notBefore = now
    if X509_gmtime_adj(X509_get_notBefore(FX509), 0) = nil then
      RaiseOpenSSLError('Failed to set notBefore');
    // notAfter = now + ValidDays
    if X509_gmtime_adj(X509_get_notAfter(FX509), Int64(ValidDays) * 24 * 60 * 60) = nil then
      RaiseOpenSSLError('Failed to set notAfter');

    // Set subject name
    SubjectName := X509_get_subject_name(FX509);
    if SubjectName = nil then
      RaiseOpenSSLError('Failed to get subject name');
    AddSubjectName(SubjectName, Subject);

    // Set issuer name (same as subject for self-signed)
    if X509_set_issuer_name(FX509, SubjectName) = 0 then
      RaiseOpenSSLError('Failed to set issuer name');

    // Set public key
    pKey := EVP_PKEY_new();
    if pKey = nil then
      RaiseOpenSSLError('Failed to create EVP_PKEY');
    try
      if EVP_PKEY_set1_RSA(pKey, FKeyPair.PublicKey.RSA) = 0 then
        RaiseOpenSSLError('Failed to set RSA key in EVP_PKEY');
      if X509_set_pubkey(FX509, pKey) = 0 then
        RaiseOpenSSLError('Failed to set public key');

      // Sign the certificate
      if X509_sign(FX509, pKey, EVP_sha256()) = 0 then
        RaiseOpenSSLError('Failed to sign certificate');
    finally
      EVP_PKEY_free(pKey);
    end;

  except
    FreeX509;
    raise;
  end;
end;

procedure TReqUtil.GenerateCSR(const Subject: TSubjectInfo; KeySize: Integer);
var
  pKey: pEVP_PKEY;
  SubjectName: pX509_NAME;
  TempStream: TMemoryStream;
begin
  FreeX509;
  FreeX509Req;

  // Free existing keys
  FPrivateKey.Free;
  FPrivateKey := nil;
  FKeyPair.Free;
  FKeyPair := nil;

  // Generate RSA key pair
  FKeyPair := TRSAKeyPair.Create;
  FKeyPair.GenerateKey(KeySize);

  // Copy private key to internal FPrivateKey via stream
  FPrivateKey := TRSAPrivateKey.Create;
  TempStream := TMemoryStream.Create;
  try
    FKeyPair.PrivateKey.SaveToStream(TempStream);
    TempStream.Position := 0;
    FPrivateKey.LoadFromStream(TempStream);
  finally
    TempStream.Free;
  end;

  // Create X509_REQ structure
  FX509Req := X509_REQ_new();
  if FX509Req = nil then
    RaiseOpenSSLError('Failed to create X509_REQ structure');

  try
    // Set version (version 1 = 0)
    if X509_REQ_set_version(FX509Req, 0) = 0 then
      RaiseOpenSSLError('Failed to set X509_REQ version');

    // Set subject name
    SubjectName := X509_REQ_get_subject_name(FX509Req);
    if SubjectName = nil then
      RaiseOpenSSLError('Failed to get subject name');
    AddSubjectName(SubjectName, Subject);

    // Set public key
    pKey := EVP_PKEY_new();
    if pKey = nil then
      RaiseOpenSSLError('Failed to create EVP_PKEY');
    try
      if EVP_PKEY_set1_RSA(pKey, FKeyPair.PublicKey.RSA) = 0 then
        RaiseOpenSSLError('Failed to set RSA key in EVP_PKEY');
      if X509_REQ_set_pubkey(FX509Req, pKey) = 0 then
        RaiseOpenSSLError('Failed to set public key');

      // Sign the request
      if X509_REQ_sign(FX509Req, pKey, EVP_sha256()) = 0 then
        RaiseOpenSSLError('Failed to sign CSR');
    finally
      EVP_PKEY_free(pKey);
    end;

  except
    FreeX509Req;
    raise;
  end;
end;

procedure TReqUtil.SaveCertificateToStream(AStream: TStream);
var
  Bio: pBIO;
  Buffer: TBytes;
  KeyLength: Integer;
begin
  if FX509 = nil then
    raise EOpenSSLError.Create('No certificate to save');

  Bio := BIO_new(BIO_s_mem);
  if Bio = nil then
    RaiseOpenSSLError('Failed to create BIO');
  try
    if PEM_write_bio_X509(Bio, FX509) = 0 then
      RaiseOpenSSLError('Failed to write certificate to BIO');

    KeyLength := BIO_pending(Bio);
    SetLength(Buffer, KeyLength);
    BIO_read(Bio, @Buffer[0], KeyLength);
    AStream.Write(Buffer[0], Length(Buffer));
  finally
    BIO_free(Bio);
  end;
end;

procedure TReqUtil.SaveCertificateToFile(const FileName: string);
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(FileName, fmCreate or fmShareDenyWrite);
  try
    SaveCertificateToStream(Stream);
  finally
    Stream.Free;
  end;
end;

procedure TReqUtil.SaveCSRToStream(AStream: TStream);
var
  Bio: pBIO;
  Buffer: TBytes;
  KeyLength: Integer;
begin
  if FX509Req = nil then
    raise EOpenSSLError.Create('No CSR to save');

  Bio := BIO_new(BIO_s_mem);
  if Bio = nil then
    RaiseOpenSSLError('Failed to create BIO');
  try
    if PEM_write_bio_X509_REQ(Bio, FX509Req) = 0 then
      RaiseOpenSSLError('Failed to write CSR to BIO');

    KeyLength := BIO_pending(Bio);
    SetLength(Buffer, KeyLength);
    BIO_read(Bio, @Buffer[0], KeyLength);
    AStream.Write(Buffer[0], Length(Buffer));
  finally
    BIO_free(Bio);
  end;
end;

procedure TReqUtil.SaveCSRToFile(const FileName: string);
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(FileName, fmCreate or fmShareDenyWrite);
  try
    SaveCSRToStream(Stream);
  finally
    Stream.Free;
  end;
end;

procedure TReqUtil.SavePrivateKeyToStream(AStream: TStream);
begin
  if FPrivateKey = nil then
    raise EOpenSSLError.Create('No private key to save');

  FPrivateKey.SaveToStream(AStream);
end;

procedure TReqUtil.SavePrivateKeyToFile(const FileName: string);
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(FileName, fmCreate or fmShareDenyWrite);
  try
    SavePrivateKeyToStream(Stream);
  finally
    Stream.Free;
  end;
end;

procedure TReqUtil.SavePublicKeyToStream(AStream: TStream);
begin
  if FKeyPair = nil then
    raise EOpenSSLError.Create('No public key to save');

  FKeyPair.PublicKey.SaveToStream(AStream);
end;

procedure TReqUtil.SavePublicKeyToFile(const FileName: string);
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(FileName, fmCreate or fmShareDenyWrite);
  try
    SavePublicKeyToStream(Stream);
  finally
    Stream.Free;
  end;
end;

end.
