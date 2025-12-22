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

    // TSubjectInfo tests
    [Test]
    procedure TestSubjectInfoImplicitFromString;
    [Test]
    procedure TestSubjectInfoImplicitToString;
    [Test]
    procedure TestSubjectInfoRoundTrip;
    [Test]
    procedure TestSubjectInfoEmpty;

    // TSerialNumber tests
    [Test]
    procedure TestSerialNumberFromInt64;
    [Test]
    procedure TestSerialNumberToInt64;
    [Test]
    procedure TestSerialNumberFromString;
    [Test]
    procedure TestSerialNumberToHexString;
    [Test]
    procedure TestSerialNumberFromBytes;
    [Test]
    procedure TestSerialNumberIsEmpty;
    [Test]
    procedure TestSerialNumberTryToInt64;
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

{ TSubjectInfo tests }

procedure TOpenSSLCoreTest.TestSubjectInfoImplicitFromString;
var
  Subject: TSubjectInfo;
begin
  Subject := '/CN=www.example.com/O=Example Inc/OU=IT/C=US/ST=California/L=San Francisco';

  Assert.AreEqual('www.example.com', Subject.CommonName);
  Assert.AreEqual('Example Inc', Subject.Organization);
  Assert.AreEqual('IT', Subject.OrganizationalUnit);
  Assert.AreEqual('US', Subject.Country);
  Assert.AreEqual('California', Subject.State);
  Assert.AreEqual('San Francisco', Subject.Locality);
end;

procedure TOpenSSLCoreTest.TestSubjectInfoImplicitToString;
var
  Subject: TSubjectInfo;
  SubjectStr: string;
begin
  Subject.CommonName := 'www.example.com';
  Subject.Organization := 'Example Inc';
  Subject.OrganizationalUnit := 'IT';
  Subject.Country := 'US';

  SubjectStr := Subject;

  Assert.IsTrue(Pos('CN=www.example.com', SubjectStr) > 0, 'Missing CommonName');
  Assert.IsTrue(Pos('O=Example Inc', SubjectStr) > 0, 'Missing Organization');
  Assert.IsTrue(Pos('OU=IT', SubjectStr) > 0, 'Missing OrganizationalUnit');
  Assert.IsTrue(Pos('C=US', SubjectStr) > 0, 'Missing Country');
end;

procedure TOpenSSLCoreTest.TestSubjectInfoRoundTrip;
var
  Original: TSubjectInfo;
  SubjectStr: string;
  Parsed: TSubjectInfo;
begin
  Original.CommonName := 'test.local';
  Original.Organization := 'Test Org';
  Original.Country := 'IT';

  SubjectStr := Original;
  Parsed := SubjectStr;

  Assert.AreEqual(Original.CommonName, Parsed.CommonName, 'CommonName mismatch');
  Assert.AreEqual(Original.Organization, Parsed.Organization, 'Organization mismatch');
  Assert.AreEqual(Original.Country, Parsed.Country, 'Country mismatch');
end;

procedure TOpenSSLCoreTest.TestSubjectInfoEmpty;
var
  Subject: TSubjectInfo;
  SubjectStr: string;
begin
  SubjectStr := '';
  Subject := SubjectStr;

  Assert.AreEqual('', Subject.CommonName);
  Assert.AreEqual('', Subject.Organization);
  Assert.AreEqual('', Subject.Country);
end;

{ TSerialNumber tests }

procedure TOpenSSLCoreTest.TestSerialNumberFromInt64;
var
  Serial: TSerialNumber;
  Value: Int64;
begin
  Value := 12345;
  Serial := Value;

  Assert.IsFalse(Serial.IsEmpty, 'Serial number should not be empty');
  Assert.IsTrue(Length(Serial.Data) > 0, 'Serial data should not be empty');
end;

procedure TOpenSSLCoreTest.TestSerialNumberToInt64;
var
  Serial: TSerialNumber;
  Value, Result: Int64;
begin
  Value := 98765;
  Serial := Value;
  Result := Serial.ToInt64;

  Assert.AreEqual(Value, Result, 'Int64 conversion failed');
end;

procedure TOpenSSLCoreTest.TestSerialNumberFromString;
var
  Serial: TSerialNumber;
  HexStr: string;
begin
  HexStr := '01:23:45:67:89:AB';
  Serial := HexStr;

  Assert.IsFalse(Serial.IsEmpty, 'Serial should not be empty');
  Assert.AreEqual(6, Length(Serial.Data), 'Should parse 6 bytes');
end;

procedure TOpenSSLCoreTest.TestSerialNumberToHexString;
var
  Serial: TSerialNumber;
  Bytes: TBytes;
  HexStr: string;
begin
  SetLength(Bytes, 3);
  Bytes[0] := $01;
  Bytes[1] := $23;
  Bytes[2] := $AB;

  Serial := Bytes;
  HexStr := Serial.ToHexString(':');

  Assert.AreEqual('01:23:AB', HexStr, 'Hex string format incorrect');
end;

procedure TOpenSSLCoreTest.TestSerialNumberFromBytes;
var
  Serial: TSerialNumber;
  Bytes: TBytes;
begin
  SetLength(Bytes, 4);
  Bytes[0] := $DE;
  Bytes[1] := $AD;
  Bytes[2] := $BE;
  Bytes[3] := $EF;

  Serial := Bytes;

  Assert.IsFalse(Serial.IsEmpty);
  Assert.AreEqual(4, Length(Serial.Data));
  Assert.AreEqual(Byte($DE), Serial.Data[0]);
  Assert.AreEqual(Byte($EF), Serial.Data[3]);
end;

procedure TOpenSSLCoreTest.TestSerialNumberIsEmpty;
var
  Serial: TSerialNumber;
  EmptyBytes: TBytes;
begin
  SetLength(EmptyBytes, 0);
  Serial := EmptyBytes;

  Assert.IsTrue(Serial.IsEmpty, 'Serial should be empty');
end;

procedure TOpenSSLCoreTest.TestSerialNumberTryToInt64;
var
  Serial: TSerialNumber;
  Value: Int64;
  Success: Boolean;
  LargeBytes: TBytes;
begin
  // Test valid conversion
  Serial := Int64(123456);
  Success := Serial.TryToInt64(Value);
  Assert.IsTrue(Success, 'TryToInt64 should succeed for small value');
  Assert.AreEqual(Int64(123456), Value);

  // Test too large (more than 8 bytes)
  SetLength(LargeBytes, 9);
  FillChar(LargeBytes[0], 9, $FF);
  Serial := LargeBytes;
  Success := Serial.TryToInt64(Value);
  Assert.IsFalse(Success, 'TryToInt64 should fail for 9-byte value');
end;

initialization
  TDUnitX.RegisterTestFixture(TOpenSSLCoreTest);

end.
