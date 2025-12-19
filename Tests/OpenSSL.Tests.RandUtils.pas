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
unit OpenSSL.Tests.RandUtils;

interface

uses
  System.SysUtils, System.IOUtils,
  DUnitX.TestFramework,

  OpenSSL.RandUtils;

type
  [TestFixture]
  TOpenSSLRandUtilsTest = class(TObject)
  public
    [Test]
    procedure TestGetRandomBytesLength;
    [Test]
    procedure TestGetPseudoRandomBytesLength;
    [Test]
    procedure TestInitializedReturnsBoolean;
    [Test]
    procedure TestGetDefaultSeedFileNameNotEmpty;
    [Test]
    procedure TestSaveSeedToFile;
  end;

implementation

uses
  OpenSSL.libeay32;

{ TOpenSSLRandUtilsTest }

procedure TOpenSSLRandUtilsTest.TestGetRandomBytesLength;
var
  Bytes: TBytes;
begin
  Bytes := TRandUtil.GetRandomBytes(16);
  Assert.AreEqual(16, Length(Bytes), 'GetRandomBytes(16) returned wrong length');

  Bytes := TRandUtil.GetRandomBytes(32);
  Assert.AreEqual(32, Length(Bytes), 'GetRandomBytes(32) returned wrong length');

  Bytes := TRandUtil.GetRandomBytes(256);
  Assert.AreEqual(256, Length(Bytes), 'GetRandomBytes(256) returned wrong length');
end;

procedure TOpenSSLRandUtilsTest.TestGetPseudoRandomBytesLength;
var
  Bytes: TBytes;
begin
  Bytes := TRandUtil.GetPseudoRandomBytes(16);
  Assert.AreEqual(16, Length(Bytes), 'GetPseudoRandomBytes(16) returned wrong length');

  Bytes := TRandUtil.GetPseudoRandomBytes(32);
  Assert.AreEqual(32, Length(Bytes), 'GetPseudoRandomBytes(32) returned wrong length');
end;

procedure TOpenSSLRandUtilsTest.TestInitializedReturnsBoolean;
var
  IsInitialized: Boolean;
begin
  IsInitialized := TRandUtil.Initialized;
  // Just verify it returns without exception
  Assert.IsTrue(IsInitialized);
end;

procedure TOpenSSLRandUtilsTest.TestGetDefaultSeedFileNameNotEmpty;
var
  FileName: string;
begin
  FileName := TRandUtil.GetDefaultSeedFileName;
  Assert.IsNotEmpty(FileName);
end;

procedure TOpenSSLRandUtilsTest.TestSaveSeedToFile;
var
  TempFile: string;
  BytesWritten: Integer;
begin
  TempFile := TPath.Combine(TPath.GetTempPath, 'test_seed.rnd');
  try
    BytesWritten := TRandUtil.SaveSeedToFile(TempFile);
    Assert.IsTrue(BytesWritten > 0, 'SaveSeedToFile should return bytes written > 0');
    Assert.IsTrue(TFile.Exists(TempFile), 'Seed file was not created');
  finally
    if TFile.Exists(TempFile) then
      TFile.Delete(TempFile);
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TOpenSSLRandUtilsTest);

end.
