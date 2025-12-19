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
unit OpenSSL.Tests.EncUtils;

interface

uses
  System.SysUtils, System.Classes,
  DUnitX.TestFramework,

  OpenSSL.EncUtils, OpenSSL.Core;

type
  [TestFixture]
  TOpenSSLEncUtilsTest = class(TObject)
  public
    [Setup]
    procedure Setup;

    [Test]
    procedure TestEncryptDecryptStream;
    [Test]
    procedure TestEncryptDecryptTBytes;
    [Test]
    procedure TestEncryptDecryptWithBase64;
    [TestCase('AES-128', 'AES-128')]
    [TestCase('AES-192', 'AES-192')]
    [TestCase('AES-256', 'AES-256')]
    [TestCase('DES3', 'DES3')]
    [TestCase('BF', 'BF')]
    procedure TestEncryptDecryptWithCipher(const CipherName: string);
    [Test]
    procedure TestEmptyInputTBytes;
    [Test]
    procedure TestKeyBasedEncryption;
    [Test]
    procedure TestEncryptDecryptStr;
    [Test]
    procedure TestEncryptDecryptStrWithEncoding;
  end;

implementation

uses
  OpenSSL.libeay32, IdSSLOpenSSLHeaders;

{ TOpenSSLEncUtilsTest }

procedure TOpenSSLEncUtilsTest.Setup;
begin
  if not LoadOpenSSLLibraryEx then
    raise EOpenSSLError.Create('Cannot open "OpenSSL" library');
end;

procedure TOpenSSLEncUtilsTest.TestEncryptDecryptStream;
var
  EncUtil: TEncUtil;
  InputStream, EncryptedStream, DecryptedStream: TMemoryStream;
  OriginalText, DecryptedText: string;
  Buffer: TBytes;
begin
  EncUtil := TEncUtil.Create;
  try
    EncUtil.Passphrase := 'TestPassword123';
    EncUtil.Cipher := 'AES-256';

    OriginalText := 'Hello from OpenSSL EncUtils!';
    InputStream := TMemoryStream.Create;
    try
      Buffer := TEncoding.UTF8.GetBytes(OriginalText);
      InputStream.Write(Buffer[0], Length(Buffer));
      InputStream.Position := 0;

      EncryptedStream := TMemoryStream.Create;
      try
        EncUtil.Encrypt(InputStream, EncryptedStream);
        Assert.IsTrue(EncryptedStream.Size > 0, 'Encrypted stream is empty');

        EncryptedStream.Position := 0;
        DecryptedStream := TMemoryStream.Create;
        try
          EncUtil.Decrypt(EncryptedStream, DecryptedStream);
          SetLength(Buffer, DecryptedStream.Size);
          DecryptedStream.Position := 0;
          DecryptedStream.Read(Buffer[0], DecryptedStream.Size);
          DecryptedText := TEncoding.UTF8.GetString(Buffer);
          Assert.AreEqual(OriginalText, DecryptedText);
        finally
          DecryptedStream.Free;
        end;
      finally
        EncryptedStream.Free;
      end;
    finally
      InputStream.Free;
    end;
  finally
    EncUtil.Free;
  end;
end;

procedure TOpenSSLEncUtilsTest.TestEncryptDecryptTBytes;
var
  EncUtil: TEncUtil;
  OriginalBytes, EncryptedBytes, DecryptedBytes: TBytes;
  OriginalText, DecryptedText: string;
begin
  EncUtil := TEncUtil.Create;
  try
    EncUtil.Passphrase := 'TestPassword123';
    EncUtil.Cipher := 'AES-256';

    OriginalText := 'Test with TBytes';
    OriginalBytes := TEncoding.UTF8.GetBytes(OriginalText);

    EncUtil.Encrypt(OriginalBytes, EncryptedBytes);
    Assert.IsTrue(Length(EncryptedBytes) > 0, 'Encrypted bytes array is empty');

    EncUtil.Decrypt(EncryptedBytes, DecryptedBytes);
    DecryptedText := TEncoding.UTF8.GetString(DecryptedBytes);
    Assert.AreEqual(OriginalText, DecryptedText);
  finally
    EncUtil.Free;
  end;
end;

procedure TOpenSSLEncUtilsTest.TestEncryptDecryptWithBase64;
var
  EncUtil: TEncUtil;
  OriginalBytes, EncryptedBytes, DecryptedBytes: TBytes;
  OriginalText, DecryptedText: string;
begin
  EncUtil := TEncUtil.Create;
  try
    EncUtil.Passphrase := 'TestPassword123';
    EncUtil.Cipher := 'AES-256';
    EncUtil.UseBase64 := True;

    OriginalText := 'Test with Base64 encoding';
    OriginalBytes := TEncoding.UTF8.GetBytes(OriginalText);

    EncUtil.Encrypt(OriginalBytes, EncryptedBytes);
    Assert.IsTrue(Length(EncryptedBytes) > 0, 'Encrypted bytes array is empty');

    EncUtil.Decrypt(EncryptedBytes, DecryptedBytes);
    DecryptedText := TEncoding.UTF8.GetString(DecryptedBytes);
    Assert.AreEqual(OriginalText, DecryptedText);
  finally
    EncUtil.Free;
  end;
end;

procedure TOpenSSLEncUtilsTest.TestEncryptDecryptWithCipher(const CipherName: string);
var
  EncUtil: TEncUtil;
  OriginalBytes, EncryptedBytes, DecryptedBytes: TBytes;
  OriginalText, DecryptedText: string;
begin
  EncUtil := TEncUtil.Create;
  try
    EncUtil.Passphrase := 'TestPassword123';
    EncUtil.Cipher := CipherName;

    OriginalText := 'Testing cipher: ' + CipherName;
    OriginalBytes := TEncoding.UTF8.GetBytes(OriginalText);

    EncUtil.Encrypt(OriginalBytes, EncryptedBytes);
    Assert.IsTrue(Length(EncryptedBytes) > 0);

    EncUtil.Decrypt(EncryptedBytes, DecryptedBytes);
    DecryptedText := TEncoding.UTF8.GetString(DecryptedBytes);
    Assert.AreEqual(OriginalText, DecryptedText);
  finally
    EncUtil.Free;
  end;
end;

procedure TOpenSSLEncUtilsTest.TestEmptyInputTBytes;
var
  EncUtil: TEncUtil;
  EmptyInput, EncryptedBytes, DecryptedBytes: TBytes;
begin
  EncUtil := TEncUtil.Create;
  try
    EncUtil.Passphrase := 'TestPassword123';
    EncUtil.Cipher := 'AES-256';

    SetLength(EmptyInput, 0);

    EncUtil.Encrypt(EmptyInput, EncryptedBytes);
    Assert.AreEqual(0, Length(EncryptedBytes), 'Empty input should produce empty encrypted output');

    EncUtil.Decrypt(EmptyInput, DecryptedBytes);
    Assert.AreEqual(0, Length(DecryptedBytes), 'Empty input should produce empty decrypted output');
  finally
    EncUtil.Free;
  end;
end;

procedure TOpenSSLEncUtilsTest.TestKeyBasedEncryption;
var
  EncUtil: TEncUtil;
  OriginalBytes, EncryptedBytes, DecryptedBytes: TBytes;
  OriginalText, DecryptedText: string;
  Key, IV: TBytes;
  Cipher: PEVP_CIPHER;
  Salt: TBytes;
begin
  EncUtil := TEncUtil.Create;
  try
    // Generate key and IV from a password
    Cipher := EVP_aes_256_cbc();
    SetLength(Salt, PKCS5_SALT_LEN);
    FillChar(Salt[0], PKCS5_SALT_LEN, $42);
    EVP_GetKeyIV('TestPassword', Cipher, Salt, Key, IV);

    // Use key-based encryption
    EncUtil.Passphrase := TPassphrase.Create(Key, IV);

    OriginalText := 'Test with key-based encryption';
    OriginalBytes := TEncoding.UTF8.GetBytes(OriginalText);

    EncUtil.Encrypt(OriginalBytes, EncryptedBytes);
    Assert.IsTrue(Length(EncryptedBytes) > 0, 'Encrypted bytes array is empty');

    EncUtil.Decrypt(EncryptedBytes, DecryptedBytes);
    DecryptedText := TEncoding.UTF8.GetString(DecryptedBytes);
    Assert.AreEqual(OriginalText, DecryptedText);
  finally
    EncUtil.Free;
  end;
end;

procedure TOpenSSLEncUtilsTest.TestEncryptDecryptStr;
var
  EncUtil: TEncUtil;
  OriginalStr, EncryptedStr, DecryptedStr: string;
begin
  EncUtil := TEncUtil.Create;
  try
    EncUtil.Passphrase := 'TestPassword123';
    EncUtil.Cipher := 'AES-256';

    OriginalStr := 'Hello from EncryptStr!';

    EncryptedStr := EncUtil.EncryptStr(OriginalStr);
    Assert.IsNotEmpty(EncryptedStr, 'Encrypted string is empty');

    DecryptedStr := EncUtil.DecryptStr(EncryptedStr);
    Assert.AreEqual(OriginalStr, DecryptedStr);
  finally
    EncUtil.Free;
  end;
end;

procedure TOpenSSLEncUtilsTest.TestEncryptDecryptStrWithEncoding;
var
  EncUtil: TEncUtil;
  OriginalStr, EncryptedStr, DecryptedStr: string;
begin
  EncUtil := TEncUtil.Create;
  try
    EncUtil.Passphrase := 'TestPassword123';
    EncUtil.Cipher := 'AES-256';

    OriginalStr := 'Unicode test: Café, naïve, 日本語';

    // Test with explicit UTF8 encoding
    EncryptedStr := EncUtil.EncryptStr(OriginalStr, TEncoding.UTF8);
    Assert.IsNotEmpty(EncryptedStr, 'Encrypted string is empty');

    DecryptedStr := EncUtil.DecryptStr(EncryptedStr, TEncoding.UTF8);
    Assert.AreEqual(OriginalStr, DecryptedStr);
  finally
    EncUtil.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TOpenSSLEncUtilsTest);

end.
