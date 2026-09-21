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
unit OpenSSL.Tests.SMIMEUtils;

interface

uses
  System.SysUtils, System.Classes, System.NetEncoding,
  DUnitX.TestFramework,

  OpenSSL.SMIMEUtils, OpenSSL.Core;

type
  [TestFixture]
  TOpenSSLSMIMEUtilsTest = class(TObject)
  private
    function CreatePKCS7Stream: TStream;
    function GetExpectedContent: TBytes;
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

const
  // DER encoded PKCS#7 produced by TestData\create_p7m.bat: test.txt signed
  // with publiccert.pem/privatekey.pem, content embedded (-nodetach).
  // Kept inline so that the tests do not depend on the TestData folder.
  PKCS7_TEST_DATA =
    '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';

{ TOpenSSLSMIMEUtilsTest }

procedure TOpenSSLSMIMEUtilsTest.Setup;
begin
  if not OpenSSL.Core.LoadOpenSSLLibrary then
    raise EOpenSSLError.Create('Cannot open "OpenSSL" library');
end;

function TOpenSSLSMIMEUtilsTest.CreatePKCS7Stream: TStream;
begin
  Result := TBytesStream.Create(TNetEncoding.Base64.DecodeStringToBytes(PKCS7_TEST_DATA));
end;

function TOpenSSLSMIMEUtilsTest.GetExpectedContent: TBytes;
begin
  // test.txt is UTF-16LE with BOM
  Result := TEncoding.Unicode.GetPreamble + TEncoding.Unicode.GetBytes('Hello, world!'#13#10);
end;

procedure TOpenSSLSMIMEUtilsTest.TestDecryptPKCS7WithVerify;
var
  SMIMEUtil: TSMIMEUtil;
  InputStream: TStream;
  OutputStream: TMemoryStream;
begin
  SMIMEUtil := TSMIMEUtil.Create;
  try
    InputStream := CreatePKCS7Stream;
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
  InputStream: TStream;
  OutputStream: TMemoryStream;
begin
  SMIMEUtil := TSMIMEUtil.Create;
  try
    InputStream := CreatePKCS7Stream;
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
  InputStream: TStream;
  OutputStream: TMemoryStream;
  Expected, OutputData: TBytes;
begin
  SMIMEUtil := TSMIMEUtil.Create;
  try
    InputStream := CreatePKCS7Stream;
    try
      OutputStream := TMemoryStream.Create;
      try
        SMIMEUtil.Decrypt(InputStream, OutputStream, True, True);

        Assert.IsTrue(OutputStream.Size > 0, 'Decrypted output is empty');

        // The signed content is the whole test.txt file
        Expected := GetExpectedContent;
        Assert.AreEqual(Int64(Integer(Length(Expected))), OutputStream.Size, 'Unexpected content length');

        SetLength(OutputData, Length(Expected));
        OutputStream.Position := 0;
        OutputStream.Read(OutputData[0], Length(OutputData));
        Assert.AreEqual(TEncoding.Unicode.GetString(Expected), TEncoding.Unicode.GetString(OutputData),
          'Output does not match the signed content');
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
