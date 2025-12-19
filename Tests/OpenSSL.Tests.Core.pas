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
unit OpenSSL.Tests.Core;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,

  OpenSSL.Core, IdSSLOpenSSLHeaders;

type
  [TestFixture]
  TOpenSSLCoreTest = class(TObject)
  public
    [Setup]
    procedure Setup;

    // Base64 Encode tests
    [Test]
    procedure TestBase64EncodeStandardText;
    [Test]
    procedure TestBase64EncodeEmptyInput;
    [Test]
    procedure TestBase64EncodeSingleChar;
    [Test]
    procedure TestBase64EncodeBinaryData;

    // Base64 Decode tests
    [Test]
    procedure TestBase64DecodeStandardText;
    [Test]
    procedure TestBase64DecodeEmptyInput;
    [Test]
    procedure TestBase64DecodeSingleChar;

    // Base64 Round-trip tests
    [Test]
    procedure TestBase64RoundTripText;
    [Test]
    procedure TestBase64RoundTripBinaryData;
    [Test]
    procedure TestBase64RoundTripUnicode;

    // EVP_GetSalt tests
    [Test]
    procedure TestEVP_GetSaltLength;
    [Test]
    procedure TestEVP_GetSaltNotAllZeros;
    [Test]
    procedure TestEVP_GetSaltUniqueness;

    // EVP_GetKeyIV tests
    [Test]
    procedure TestEVP_GetKeyIVWithStringPassword;
    [Test]
    procedure TestEVP_GetKeyIVWithBytesPassword;
    [Test]
    procedure TestEVP_GetKeyIVDifferentPasswords;
  end;

implementation

uses
  OpenSSL.libeay32;

{ TOpenSSLCoreTest }

procedure TOpenSSLCoreTest.Setup;
begin
  if not LoadOpenSSLLibraryEx then
    raise EOpenSSLError.Create('Cannot open "OpenSSL" library');
end;

{ Base64 Encode tests }

procedure TOpenSSLCoreTest.TestBase64EncodeStandardText;
var
  Input: TBytes;
  Output: TBytes;
  Expected: string;
begin
  Input := TEncoding.ASCII.GetBytes('Hello World!');
  Output := Base64Encode(Input);
  Expected := 'SGVsbG8gV29ybGQh' + #10;  // OpenSSL adds newline
  Assert.AreEqual(Expected, TEncoding.ASCII.GetString(Output));
end;

procedure TOpenSSLCoreTest.TestBase64EncodeEmptyInput;
var
  Input: TBytes;
  Output: TBytes;
begin
  SetLength(Input, 0);
  Output := Base64Encode(Input);
  Assert.AreEqual(0, Length(Output));
end;

procedure TOpenSSLCoreTest.TestBase64EncodeSingleChar;
var
  Input: TBytes;
  Output: TBytes;
  Expected: string;
begin
  Input := TEncoding.ASCII.GetBytes('A');
  Output := Base64Encode(Input);
  Expected := 'QQ==' + #10;
  Assert.AreEqual(Expected, TEncoding.ASCII.GetString(Output));
end;

procedure TOpenSSLCoreTest.TestBase64EncodeBinaryData;
var
  Input: TBytes;
  Output: TBytes;
begin
  SetLength(Input, 3);
  Input[0] := $00;
  Input[1] := $FF;
  Input[2] := $7F;
  Output := Base64Encode(Input);
  Assert.IsTrue(Length(Output) > 0);
end;

{ Base64 Decode tests }

procedure TOpenSSLCoreTest.TestBase64DecodeStandardText;
var
  Input: TBytes;
  Output: TBytes;
  Expected: string;
begin
  Input := TEncoding.ASCII.GetBytes('SGVsbG8gV29ybGQh' + #10);  // "Hello World!" with newline
  Output := Base64Decode(Input);
  Expected := 'Hello World!';
  Assert.AreEqual(Expected, TEncoding.ASCII.GetString(Output));
end;

procedure TOpenSSLCoreTest.TestBase64DecodeEmptyInput;
var
  Input: TBytes;
  Output: TBytes;
begin
  SetLength(Input, 0);
  Output := Base64Decode(Input);
  Assert.AreEqual(0, Length(Output));
end;

procedure TOpenSSLCoreTest.TestBase64DecodeSingleChar;
var
  Input: TBytes;
  Output: TBytes;
begin
  Input := TEncoding.ASCII.GetBytes('QQ==' + #10);  // "A"
  Output := Base64Decode(Input);
  Assert.AreEqual('A', TEncoding.ASCII.GetString(Output));
end;

{ Base64 Round-trip tests }

procedure TOpenSSLCoreTest.TestBase64RoundTripText;
var
  Original: TBytes;
  Encoded: TBytes;
  Decoded: TBytes;
  TestString: string;
begin
  TestString := 'The quick brown fox jumps over the lazy dog';
  Original := TEncoding.UTF8.GetBytes(TestString);
  Encoded := Base64Encode(Original);
  Decoded := Base64Decode(Encoded);
  Assert.AreEqual(TestString, TEncoding.UTF8.GetString(Decoded));
end;

procedure TOpenSSLCoreTest.TestBase64RoundTripBinaryData;
var
  Original: TBytes;
  Encoded: TBytes;
  Decoded: TBytes;
  i: Integer;
begin
  SetLength(Original, 256);
  for i := 0 to 255 do
    Original[i] := Byte(i);
  Encoded := Base64Encode(Original);
  Decoded := Base64Decode(Encoded);
  Assert.AreEqual(Length(Original), Length(Decoded), 'Decoded length does not match original');
  for i := 0 to 255 do
    Assert.AreEqual(Original[i], Decoded[i], Format('Byte mismatch at position %d', [i]));
end;

procedure TOpenSSLCoreTest.TestBase64RoundTripUnicode;
var
  Original: TBytes;
  Encoded: TBytes;
  Decoded: TBytes;
  TestString: string;
begin
  TestString := 'Café, naïve, 日本語, emoji: 🔒';
  Original := TEncoding.UTF8.GetBytes(TestString);
  Encoded := Base64Encode(Original);
  Decoded := Base64Decode(Encoded);
  Assert.AreEqual(TestString, TEncoding.UTF8.GetString(Decoded));
end;

{ EVP_GetSalt tests }

procedure TOpenSSLCoreTest.TestEVP_GetSaltLength;
var
  Salt: TBytes;
begin
  Salt := EVP_GetSalt;
  Assert.AreEqual(PKCS5_SALT_LEN, Length(Salt));
end;

procedure TOpenSSLCoreTest.TestEVP_GetSaltNotAllZeros;
var
  Salt: TBytes;
  i: Integer;
  AllZeros: Boolean;
begin
  Salt := EVP_GetSalt;
  AllZeros := True;
  for i := 0 to Length(Salt) - 1 do
    if Salt[i] <> 0 then
    begin
      AllZeros := False;
      Break;
    end;
  Assert.IsFalse(AllZeros);
end;

procedure TOpenSSLCoreTest.TestEVP_GetSaltUniqueness;
var
  Salt1, Salt2: TBytes;
begin
  Salt1 := EVP_GetSalt;
  Salt2 := EVP_GetSalt;
  Assert.AreNotEqual(TEncoding.ASCII.GetString(Salt1), TEncoding.ASCII.GetString(Salt2));
end;

{ EVP_GetKeyIV tests }

procedure TOpenSSLCoreTest.TestEVP_GetKeyIVWithStringPassword;
var
  Password: string;
  Salt: TBytes;
  Key, IV: TBytes;
  Cipher: PEVP_CIPHER;
begin
  Password := 'TestPassword123';
  SetLength(Salt, PKCS5_SALT_LEN);
  FillChar(Salt[0], PKCS5_SALT_LEN, $42);
  Cipher := EVP_aes_256_cbc();

  EVP_GetKeyIV(Password, Cipher, Salt, Key, IV);

  Assert.AreEqual(EVP_MAX_KEY_LENGTH, Length(Key), 'Key length incorrect');
  Assert.AreEqual(EVP_MAX_IV_LENGTH, Length(IV), 'IV length incorrect');
end;

procedure TOpenSSLCoreTest.TestEVP_GetKeyIVWithBytesPassword;
var
  Password: string;
  PasswordBytes: TBytes;
  Salt: TBytes;
  Key, IV: TBytes;
  Cipher: PEVP_CIPHER;
begin
  Password := 'TestPassword123';
  PasswordBytes := TEncoding.UTF8.GetBytes(Password);
  SetLength(Salt, PKCS5_SALT_LEN);
  FillChar(Salt[0], PKCS5_SALT_LEN, $42);
  Cipher := EVP_aes_256_cbc();

  EVP_GetKeyIV(PasswordBytes, Cipher, Salt, Key, IV);

  Assert.AreEqual(EVP_MAX_KEY_LENGTH, Length(Key), 'Key length incorrect (TBytes overload)');
  Assert.AreEqual(EVP_MAX_IV_LENGTH, Length(IV), 'IV length incorrect (TBytes overload)');
end;

procedure TOpenSSLCoreTest.TestEVP_GetKeyIVDifferentPasswords;
var
  Salt: TBytes;
  Key1, IV1, Key2, IV2: TBytes;
  Cipher: PEVP_CIPHER;
begin
  SetLength(Salt, PKCS5_SALT_LEN);
  FillChar(Salt[0], PKCS5_SALT_LEN, $42);
  Cipher := EVP_aes_256_cbc();

  EVP_GetKeyIV('Password1', Cipher, Salt, Key1, IV1);
  EVP_GetKeyIV('Password2', Cipher, Salt, Key2, IV2);

  Assert.AreNotEqual(TEncoding.ASCII.GetString(Key1), TEncoding.ASCII.GetString(Key2));
end;

initialization
  TDUnitX.RegisterTestFixture(TOpenSSLCoreTest);

end.
