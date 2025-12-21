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
unit OpenSSL.Tests.ReqUtils;

interface

uses
  System.SysUtils, System.Classes,
  DUnitX.TestFramework,
  OpenSSL.ReqUtils, OpenSSL.Core, OpenSSL.RSAUtils;

type
  [TestFixture]
  TOpenSSLReqUtilsTest = class(TObject)
  public
    [Setup]
    procedure Setup;

    // Subject parsing tests
    [Test]
    procedure TestSubjectInfoParseSimple;
    [Test]
    procedure TestSubjectInfoParseWithSpaces;
    [Test]
    procedure TestSubjectInfoParseWithQuotes;
    [Test]
    procedure TestSubjectInfoToString;
    [Test]
    procedure TestSubjectInfoRoundTrip;

    // Certificate generation tests
    [Test]
    procedure TestGenerateSelfSignedCertificate;
    [Test]
    procedure TestSaveCertificateToStream;
    [Test]
    procedure TestCertificateValidity;

    // CSR generation tests
    [Test]
    procedure TestGenerateCSR;
    [Test]
    procedure TestSaveCSRToStream;

    // Key tests
    [Test]
    procedure TestPrivateKeyAccessible;
    [Test]
    procedure TestPublicKeyAccessible;
  end;

implementation

uses
  OpenSSL.libeay32;

{ TOpenSSLReqUtilsTest }

procedure TOpenSSLReqUtilsTest.Setup;
begin
  if not LoadOpenSSLLibraryEx then
    raise EOpenSSLError.Create('Cannot open "OpenSSL" library');
end;

procedure TOpenSSLReqUtilsTest.TestSubjectInfoParseSimple;
var
  Subject: TSubjectInfo;
begin
  Subject := 'CN=localhost,O=MyCompany,C=IT';
  Assert.AreEqual('localhost', Subject.CommonName, 'CommonName mismatch');
  Assert.AreEqual('MyCompany', Subject.Organization, 'Organization mismatch');
  Assert.AreEqual('IT', Subject.Country, 'Country mismatch');
end;

procedure TOpenSSLReqUtilsTest.TestSubjectInfoParseWithSpaces;
var
  Subject: TSubjectInfo;
begin
  Subject := 'CN=localhost, O=My Company, C=IT';
  Assert.AreEqual('localhost', Subject.CommonName, 'CommonName mismatch');
  Assert.AreEqual('My Company', Subject.Organization, 'Organization mismatch');
  Assert.AreEqual('IT', Subject.Country, 'Country mismatch');
end;

procedure TOpenSSLReqUtilsTest.TestSubjectInfoParseWithQuotes;
var
  Subject: TSubjectInfo;
begin
  Subject := 'CN="localhost, server",O=MyCompany,C=IT';
  Assert.AreEqual('localhost, server', Subject.CommonName, 'Quoted CommonName mismatch');
  Assert.AreEqual('MyCompany', Subject.Organization, 'Organization mismatch');
  Assert.AreEqual('IT', Subject.Country, 'Country mismatch');
end;

procedure TOpenSSLReqUtilsTest.TestSubjectInfoToString;
var
  Subject: TSubjectInfo;
  Result: string;
begin
  Subject.CommonName := 'localhost';
  Subject.Organization := 'MyCompany';
  Subject.Country := 'IT';

  Result := Subject;
  Assert.IsTrue(Result.Contains('CN=localhost'), 'Missing CN in output');
  Assert.IsTrue(Result.Contains('O=MyCompany'), 'Missing O in output');
  Assert.IsTrue(Result.Contains('C=IT'), 'Missing C in output');
end;

procedure TOpenSSLReqUtilsTest.TestSubjectInfoRoundTrip;
var
  Original, Parsed: TSubjectInfo;
  Str: string;
begin
  Original.CommonName := 'localhost';
  Original.Organization := 'My Company';
  Original.Country := 'IT';
  Original.State := 'California';

  Str := Original;
  Parsed := Str;

  Assert.AreEqual(Original.CommonName, Parsed.CommonName, 'CommonName roundtrip failed');
  Assert.AreEqual(Original.Organization, Parsed.Organization, 'Organization roundtrip failed');
  Assert.AreEqual(Original.Country, Parsed.Country, 'Country roundtrip failed');
  Assert.AreEqual(Original.State, Parsed.State, 'State roundtrip failed');
end;

procedure TOpenSSLReqUtilsTest.TestGenerateSelfSignedCertificate;
var
  ReqUtil: TReqUtil;
  Subject: TSubjectInfo;
begin
  ReqUtil := TReqUtil.Create;
  try
    Subject := 'CN=localhost,O=TestCompany,C=IT';
    ReqUtil.GenerateSelfSignedCertificate(Subject, 365, 1024);

    Assert.IsNotNull(ReqUtil.PrivateKey, 'PrivateKey should not be nil');
    Assert.IsTrue(ReqUtil.PrivateKey.IsValid, 'PrivateKey should be valid');
  finally
    ReqUtil.Free;
  end;
end;

procedure TOpenSSLReqUtilsTest.TestSaveCertificateToStream;
var
  ReqUtil: TReqUtil;
  Subject: TSubjectInfo;
  Stream: TMemoryStream;
  Buffer: TBytes;
  Content: string;
begin
  ReqUtil := TReqUtil.Create;
  try
    Subject := 'CN=localhost,O=TestCompany,C=IT';
    ReqUtil.GenerateSelfSignedCertificate(Subject, 365, 1024);

    Stream := TMemoryStream.Create;
    try
      ReqUtil.SaveCertificateToStream(Stream);
      Assert.IsTrue(Stream.Size > 0, 'Certificate stream is empty');

      // Verify PEM format
      Stream.Position := 0;
      SetLength(Buffer, Stream.Size);
      Stream.Read(Buffer[0], Stream.Size);
      Content := TEncoding.ASCII.GetString(Buffer);
      Assert.IsTrue(Content.Contains('BEGIN CERTIFICATE'), 'Missing PEM header');
      Assert.IsTrue(Content.Contains('END CERTIFICATE'), 'Missing PEM footer');
    finally
      Stream.Free;
    end;
  finally
    ReqUtil.Free;
  end;
end;

procedure TOpenSSLReqUtilsTest.TestCertificateValidity;
var
  ReqUtil: TReqUtil;
  Subject: TSubjectInfo;
  Certificate: TX509Cerificate;
  CertStream: TMemoryStream;
begin
  ReqUtil := TReqUtil.Create;
  try
    Subject := 'CN=localhost,O=TestCompany,C=IT';
    ReqUtil.GenerateSelfSignedCertificate(Subject, 365, 1024);

    // Save and reload certificate
    CertStream := TMemoryStream.Create;
    try
      ReqUtil.SaveCertificateToStream(CertStream);
      CertStream.Position := 0;

      Certificate := TX509Cerificate.Create;
      try
        Certificate.LoadFromStream(CertStream);
        Assert.IsTrue(Certificate.IsValid, 'Loaded certificate is not valid');
      finally
        Certificate.Free;
      end;
    finally
      CertStream.Free;
    end;
  finally
    ReqUtil.Free;
  end;
end;

procedure TOpenSSLReqUtilsTest.TestGenerateCSR;
var
  ReqUtil: TReqUtil;
  Subject: TSubjectInfo;
begin
  ReqUtil := TReqUtil.Create;
  try
    Subject := 'CN=localhost,O=TestCompany,C=IT';
    ReqUtil.GenerateCSR(Subject, 1024);

    Assert.IsNotNull(ReqUtil.PrivateKey, 'PrivateKey should not be nil');
    Assert.IsTrue(ReqUtil.PrivateKey.IsValid, 'PrivateKey should be valid');
  finally
    ReqUtil.Free;
  end;
end;

procedure TOpenSSLReqUtilsTest.TestSaveCSRToStream;
var
  ReqUtil: TReqUtil;
  Subject: TSubjectInfo;
  Stream: TMemoryStream;
  Buffer: TBytes;
  Content: string;
begin
  ReqUtil := TReqUtil.Create;
  try
    Subject := 'CN=localhost,O=TestCompany,C=IT';
    ReqUtil.GenerateCSR(Subject, 1024);

    Stream := TMemoryStream.Create;
    try
      ReqUtil.SaveCSRToStream(Stream);
      Assert.IsTrue(Stream.Size > 0, 'CSR stream is empty');

      // Verify PEM format
      Stream.Position := 0;
      SetLength(Buffer, Stream.Size);
      Stream.Read(Buffer[0], Stream.Size);
      Content := TEncoding.ASCII.GetString(Buffer);
      Assert.IsTrue(Content.Contains('BEGIN CERTIFICATE REQUEST'), 'Missing CSR PEM header');
      Assert.IsTrue(Content.Contains('END CERTIFICATE REQUEST'), 'Missing CSR PEM footer');
    finally
      Stream.Free;
    end;
  finally
    ReqUtil.Free;
  end;
end;

procedure TOpenSSLReqUtilsTest.TestPrivateKeyAccessible;
var
  ReqUtil: TReqUtil;
  Subject: TSubjectInfo;
  Stream: TMemoryStream;
  Buffer: TBytes;
  Content: string;
begin
  ReqUtil := TReqUtil.Create;
  try
    Subject := 'CN=localhost,O=TestCompany,C=IT';
    ReqUtil.GenerateSelfSignedCertificate(Subject, 365, 1024);

    // Save private key to stream
    Stream := TMemoryStream.Create;
    try
      ReqUtil.SavePrivateKeyToStream(Stream);
      Assert.IsTrue(Stream.Size > 0, 'Private key stream is empty');

      // Verify PEM format
      Stream.Position := 0;
      SetLength(Buffer, Stream.Size);
      Stream.Read(Buffer[0], Stream.Size);
      Content := TEncoding.ASCII.GetString(Buffer);
      Assert.IsTrue(Content.Contains('BEGIN'), 'Missing PEM header');
      Assert.IsTrue(Content.Contains('PRIVATE KEY'), 'Missing PRIVATE KEY marker');
      Assert.IsTrue(Content.Contains('END'), 'Missing PEM footer');
    finally
      Stream.Free;
    end;
  finally
    ReqUtil.Free;
  end;
end;

procedure TOpenSSLReqUtilsTest.TestPublicKeyAccessible;
var
  ReqUtil: TReqUtil;
  Subject: TSubjectInfo;
  Stream: TMemoryStream;
  Buffer: TBytes;
  Content: string;
begin
  ReqUtil := TReqUtil.Create;
  try
    Subject := 'CN=localhost,O=TestCompany,C=IT';
    ReqUtil.GenerateSelfSignedCertificate(Subject, 365, 1024);

    // Save public key to stream
    Stream := TMemoryStream.Create;
    try
      ReqUtil.SavePublicKeyToStream(Stream);
      Assert.IsTrue(Stream.Size > 0, 'Public key stream is empty');

      // Verify PEM format
      Stream.Position := 0;
      SetLength(Buffer, Stream.Size);
      Stream.Read(Buffer[0], Stream.Size);
      Content := TEncoding.ASCII.GetString(Buffer);
      Assert.IsTrue(Content.Contains('BEGIN'), 'Missing PEM header');
      Assert.IsTrue(Content.Contains('PUBLIC KEY'), 'Missing PUBLIC KEY marker');
      Assert.IsTrue(Content.Contains('END'), 'Missing PEM footer');
    finally
      Stream.Free;
    end;
  finally
    ReqUtil.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TOpenSSLReqUtilsTest);

end.
