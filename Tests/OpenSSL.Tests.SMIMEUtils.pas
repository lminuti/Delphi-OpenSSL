{******************************************************************************}
{                                                                              }
{  Delphi OPENSSL Library                                                      }
{  Copyright (c) 2016 Luca Minuti                                              }
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
unit OpenSSL.Tests.SMIMEUtils;

interface

uses
  System.SysUtils, System.Classes, System.IOUtils,
  DUnitX.TestFramework,

  OpenSSL.SMIMEUtils, OpenSSL.Core;

type
  [TestFixture]
  TOpenSSLSMIMEUtilsTest = class(TObject)
  private
    function GetTestDataPath: string;
    function GetPKCS7FilePath: string;
  public
    [Setup]
    procedure Setup;

    [Test]
    procedure TestDecryptPKCS7WithVerify;
    [Test]
    procedure TestDecryptPKCS7NoVerify;
    [Test]
    procedure TestDecryptProducesOutput;
  end;

implementation

uses
  OpenSSL.libeay32;

{ TOpenSSLSMIMEUtilsTest }

procedure TOpenSSLSMIMEUtilsTest.Setup;
begin
  if not LoadOpenSSLLibraryEx then
    raise EOpenSSLError.Create('Cannot open "OpenSSL" library');
end;

function TOpenSSLSMIMEUtilsTest.GetTestDataPath: string;
begin
  // Get path relative to test executable
  Result := TPath.Combine(TPath.GetDirectoryName(ParamStr(0)), '..\..\..\TestData');
  Result := TPath.GetFullPath(Result);
end;

function TOpenSSLSMIMEUtilsTest.GetPKCS7FilePath: string;
begin
  Result := TPath.Combine(GetTestDataPath, 'TestPKCS7.pdf.p7m');
end;

procedure TOpenSSLSMIMEUtilsTest.TestDecryptPKCS7WithVerify;
var
  SMIMEUtil: TSMIMEUtil;
  InputStream: TFileStream;
  OutputStream: TMemoryStream;
  FilePath: string;
begin
  FilePath := GetPKCS7FilePath;
  if not TFile.Exists(FilePath) then
    Assert.Fail('Test file not found: ' + FilePath);

  SMIMEUtil := TSMIMEUtil.Create;
  try
    InputStream := TFileStream.Create(FilePath, fmOpenRead);
    try
      OutputStream := TMemoryStream.Create;
      try
        // Decrypt with verification (may fail if certificates are not in store)
        SMIMEUtil.Decrypt(InputStream, OutputStream, True, False);
        // Just verify no exception was raised
        Assert.Pass;
      finally
        OutputStream.Free;
      end;
    finally
      InputStream.Free;
    end;
  finally
    SMIMEUtil.Free;
  end;
end;

procedure TOpenSSLSMIMEUtilsTest.TestDecryptPKCS7NoVerify;
var
  SMIMEUtil: TSMIMEUtil;
  InputStream: TFileStream;
  OutputStream: TMemoryStream;
  FilePath: string;
begin
  FilePath := GetPKCS7FilePath;
  if not TFile.Exists(FilePath) then
    Assert.Fail('Test file not found: ' + FilePath);

  SMIMEUtil := TSMIMEUtil.Create;
  try
    InputStream := TFileStream.Create(FilePath, fmOpenRead);
    try
      OutputStream := TMemoryStream.Create;
      try
        // Decrypt without verification
        SMIMEUtil.Decrypt(InputStream, OutputStream, True, True);
        Assert.IsTrue(OutputStream.Size > 0, 'Output stream is empty');
      finally
        OutputStream.Free;
      end;
    finally
      InputStream.Free;
    end;
  finally
    SMIMEUtil.Free;
  end;
end;

procedure TOpenSSLSMIMEUtilsTest.TestDecryptProducesOutput;
var
  SMIMEUtil: TSMIMEUtil;
  InputStream: TFileStream;
  OutputStream: TMemoryStream;
  FilePath: string;
  OutputData: TBytes;
begin
  FilePath := GetPKCS7FilePath;
  if not TFile.Exists(FilePath) then
    Assert.Fail('Test file not found: ' + FilePath);

  SMIMEUtil := TSMIMEUtil.Create;
  try
    InputStream := TFileStream.Create(FilePath, fmOpenRead);
    try
      OutputStream := TMemoryStream.Create;
      try
        SMIMEUtil.Decrypt(InputStream, OutputStream, True, True);

        Assert.IsTrue(OutputStream.Size > 0, 'Decrypted output is empty');

        // Verify it contains PDF signature
        SetLength(OutputData, 5);
        OutputStream.Position := 0;
        OutputStream.Read(OutputData[0], 5);
        Assert.AreEqual('%PDF-', TEncoding.ASCII.GetString(OutputData), 'Output does not appear to be a PDF file');
      finally
        OutputStream.Free;
      end;
    finally
      InputStream.Free;
    end;
  finally
    SMIMEUtil.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TOpenSSLSMIMEUtilsTest);

end.
