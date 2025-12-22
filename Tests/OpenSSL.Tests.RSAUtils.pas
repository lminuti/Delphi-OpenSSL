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
unit OpenSSL.Tests.RSAUtils;

interface

uses
  System.SysUtils, System.Classes,
  DUnitX.TestFramework,

  OpenSSL.RSAUtils, OpenSSL.Core;

type
  [TestFixture]
  TOpenSSLRSAUtilsTest = class(TObject)
  private
    FPublicKeyStream: TStringStream;
    FPrivateKeyStream: TStringStream;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    procedure TestLoadPublicKeyFromPEM;
    [Test]
    procedure TestLoadPrivateKeyFromPEM;
    [Test]
    procedure TestLoadCertificate;
    [Test]
    procedure TestPublicKeyFromCertificate;
    [Test]
    procedure TestGenerateKeyPair;
    [Test]
    procedure TestEncryptDecryptWithPublicPrivateKey;
    [Test]
    procedure TestSaveLoadPublicKey;
    [Test]
    procedure TestSaveLoadPrivateKey;
    [Test]
    procedure TestCertificateSubject;
    [Test]
    procedure TestCertificateIssuer;
    [Test]
    procedure TestCertificateSerialNumber;
    [Test]
    procedure TestCertificateDates;
    [Test]
    procedure TestCertificateVersion;
    [Test]
    procedure TestCertificateIsValid;
    [Test]
    procedure TestCertificateDaysUntilExpiration;
    [Test]
    procedure TestPrintCertificateInfo;
  end;

implementation

uses
  OpenSSL.libeay32;

const
  // Test public key (PEM format)
  TEST_PUBLIC_KEY =
    '-----BEGIN PUBLIC KEY-----' + #13#10 +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzPndv/kKQNQ1GwpHrvHr' + #13#10 +
    'gDWG/YDTkaEFoIVnXff/cxwQWzrnQiR6jtWZPDLd1vLy5soUkVjaqN/QBVRTWYVd' + #13#10 +
    'FfRtud4my7FyiOUajX3jZeblQ5y/DKMk/3aSnRJeQVGMtJn0k+JoYAnGZiGamTEa' + #13#10 +
    'eXNOs5O26cZsPfbnGgSnNY8J1iWWBHeqJm7hu1dz7mi2JDgftWGyXeRVt13lLJFA' + #13#10 +
    'pjhVh0r2jBxw6nTlqOdjBLZRomjbUQkIsRE6OVk2el9jk6kkwm/HPjV59EpDPlEX' + #13#10 +
    'm9UPgSNcvmdV66SSflsoAqBGBES1sY9vYux9A4rM7ahJsx4ef11uNAioeVG4zsNS' + #13#10 +
    'KQIDAQAB' + #13#10 +
    '-----END PUBLIC KEY-----' + #13#10;

  // Test private key (PEM format)
  TEST_PRIVATE_KEY =
    '-----BEGIN PRIVATE KEY-----' + #13#10 +
    'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDM+d2/+QpA1DUb' + #13#10 +
    'Ckeu8euANYb9gNORoQWghWdd9/9zHBBbOudCJHqO1Zk8Mt3W8vLmyhSRWNqo39AF' + #13#10 +
    'VFNZhV0V9G253ibLsXKI5RqNfeNl5uVDnL8MoyT/dpKdEl5BUYy0mfST4mhgCcZm' + #13#10 +
    'IZqZMRp5c06zk7bpxmw99ucaBKc1jwnWJZYEd6ombuG7V3PuaLYkOB+1YbJd5FW3' + #13#10 +
    'XeUskUCmOFWHSvaMHHDqdOWo52MEtlGiaNtRCQixETo5WTZ6X2OTqSTCb8c+NXn0' + #13#10 +
    'SkM+UReb1Q+BI1y+Z1XrpJJ+WygCoEYERLWxj29i7H0DisztqEmzHh5/XW40CKh5' + #13#10 +
    'UbjOw1IpAgMBAAECggEBAKQnc0yb4Hc8u271U6UqfyTFOV9pvYYCQ6RjUf3yb3S7' + #13#10 +
    'Q+ocCTpyRmh/bWHFht3u4VKtAb3JQAxAebLa7oliAcNkZj+VRtKYQJabjCFGcUeZ' + #13#10 +
    'm4ADVwmC2k1wo0gBftSmv52fMj0A8//9tBL01H/c0Ev1aVDtem5MB0G0qy2uDk8X' + #13#10 +
    '1xbUY6vGgqWzkDKGyIU8PNME4NZgmquTESkiPPCK2GwdlZ5fMZbHwobTjEZqQimm' + #13#10 +
    '/7tNwrG+QEz3+VNfH/x8UHlaDBKjzm4bsxhLtODeLHPbXVGljJXDZd+8hvBjcnjt' + #13#10 +
    'w3cRPjJak8Skmwxk2hlBqvDOrgH8pjtsHHwF/b3ATRUCgYEA+1gsNbmdWCE4w8sE' + #13#10 +
    'fjsicqO2lvjxTU4fD7wuwThKQ+hAmuhqxIqwq1S+sgZQKuyP+83aFfEYt5a6yFTC' + #13#10 +
    'm29spNKpXSH4yg32eeF9hRh8Q7A9YkzJIvLmCes1PrHAA9ESnlfH0o0CHZ0Btr+5' + #13#10 +
    'S7vjOy+6NtnNYPMnRbZFBUD2BGsCgYEA0MXSz7/Pv6SdXHvMdczZTFRDS/6JtE6N' + #13#10 +
    'H7hutasQ2KSsKXCFJonZpcyzhL6hG6iQgPdXnEOXKgNKLSRF0QPfz4ASMgrnbn7C' + #13#10 +
    'ivjwllgJPGNjCC5fiAyj8bKMMwg0DefzDtrihSxXttSpAvJqt4j460j2qZsBILM0' + #13#10 +
    'VZ29GHFwSLsCgYBVj/CM4YEkzTprvKLs7eiOKhkwT9KlRGDilGc+M5FkiJ3lnhUq' + #13#10 +
    'jyQRTyoTpH6J/joNuEfzjD2j0dYH+IK/MzFC8svg/n2ZGyO63f5C3tD+ofJjkkwu' + #13#10 +
    'b43L9pwLmasKIZQ6/xrxHDuKJTa+JYpIs89pCJhVr9Nwm5XU73WTkketvQKBgQCd' + #13#10 +
    '59JwYdLfT8HZ7qURwHPmwKD5/Lbo0rT49gV+kLm4Mq0o1rtPD9q4BeEOGSVABzns' + #13#10 +
    '4ae5QII4O67B//pygeypRGP+x7KOJ4A7nthRzpqFu2JvEKwe+fiSWgqimqTMk9CK' + #13#10 +
    'PtIwCf76AVUoLnS7BvXG+DPgyqWKtyBxVVJuB3b2+wKBgDEmXO1mW0ZX4n4x9MyQ' + #13#10 +
    'DkFYc0WgxG/XTCCvoXwZMY8dTzh4OdzyvgQSzPh2XcEBvmhehbQE0J0MfR3kRnRj' + #13#10 +
    'hBzyFDV3cfvLyUaa4jDSoHH9ihweuZ2IX+Ee2BikHg80vkf40DiwTJZwwk8fC4Yu' + #13#10 +
    '0ib5E+cQgT5Y+R3IOUiI7hpE' + #13#10 +
    '-----END PRIVATE KEY-----' + #13#10;

  // Test certificate (PEM format)
  TEST_CERTIFICATE =
    '-----BEGIN CERTIFICATE-----' + #13#10 +
    'MIIDajCCAlICCQDmjJzqdvPg4zANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJJ' + #13#10 +
    'VDESMBAGA1UECAwJTG9tYmFyZGlhMQ8wDQYDVQQHDAZNaWxhbm8xFzAVBgNVBAoM' + #13#10 +
    'DkxhIE1pYSBBemllbmRhMRYwFAYDVQQLDA1JVCBEZXBhcnRtZW50MRIwEAYDVQQD' + #13#10 +
    'DAlsb2NhbGhvc3QwHhcNMjUxMjE5MTAyMzU2WhcNMzUxMjE3MTAyMzU2WjB3MQsw' + #13#10 +
    'CQYDVQQGEwJJVDESMBAGA1UECAwJTG9tYmFyZGlhMQ8wDQYDVQQHDAZNaWxhbm8x' + #13#10 +
    'FzAVBgNVBAoMDkxhIE1pYSBBemllbmRhMRYwFAYDVQQLDA1JVCBEZXBhcnRtZW50' + #13#10 +
    'MRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK' + #13#10 +
    'AoIBAQDM+d2/+QpA1DUbCkeu8euANYb9gNORoQWghWdd9/9zHBBbOudCJHqO1Zk8' + #13#10 +
    'Mt3W8vLmyhSRWNqo39AFVFNZhV0V9G253ibLsXKI5RqNfeNl5uVDnL8MoyT/dpKd' + #13#10 +
    'El5BUYy0mfST4mhgCcZmIZqZMRp5c06zk7bpxmw99ucaBKc1jwnWJZYEd6ombuG7' + #13#10 +
    'V3PuaLYkOB+1YbJd5FW3XeUskUCmOFWHSvaMHHDqdOWo52MEtlGiaNtRCQixETo5' + #13#10 +
    'WTZ6X2OTqSTCb8c+NXn0SkM+UReb1Q+BI1y+Z1XrpJJ+WygCoEYERLWxj29i7H0D' + #13#10 +
    'isztqEmzHh5/XW40CKh5UbjOw1IpAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMDN' + #13#10 +
    'CA0OwNCj3YjOTpTZrTREz29ciqep3lNZKl++QiLc9Up68OA01ydIn6DHeisY1Ux7' + #13#10 +
    '9ko/iPFC/+RAzL07itks9RgZsEdIXM//8nSHTc99c732G3wGDuzUCPNnIlotsrH+' + #13#10 +
    'lPr9pBkEb9tlLkCueAz02FavPMxfzRdGEVSWbXczSV1kARF7VtrBskMr44LMQowQ' + #13#10 +
    'PQ+S5LkaI+tMLgUigH14mMUmEEg4UKYXWKG+OGKJaAMQmUWREfGUYD+E+dbV4bTz' + #13#10 +
    '9GbSq+q6FG1SiWpoU/8XBVxBLPi7/E22zP3haXUpBAyWgTK4OTK6VR1qXIM4vXXe' + #13#10 +
    'zPF+LMurlVPWW9drurw=' + #13#10 +
    '-----END CERTIFICATE-----' + #13#10;

{ TOpenSSLRSAUtilsTest }

procedure TOpenSSLRSAUtilsTest.Setup;
begin
  if not LoadOpenSSLLibraryEx then
    raise EOpenSSLError.Create('Cannot open "OpenSSL" library');

  FPublicKeyStream := TStringStream.Create(TEST_PUBLIC_KEY, TEncoding.UTF8);
  FPrivateKeyStream := TStringStream.Create(TEST_PRIVATE_KEY, TEncoding.UTF8);;
end;

procedure TOpenSSLRSAUtilsTest.TestLoadPublicKeyFromPEM;
var
  PublicKey: TRSAPublicKey;
  Stream: TStringStream;
begin
  PublicKey := TRSAPublicKey.Create;
  try
    Stream := TStringStream.Create(TEST_PUBLIC_KEY, TEncoding.UTF8);
    try
      PublicKey.LoadFromStream(Stream);
      Assert.IsTrue(PublicKey.IsValid);
    finally
      Stream.Free;
    end;
  finally
    PublicKey.Free;
  end;
end;

procedure TOpenSSLRSAUtilsTest.TestLoadPrivateKeyFromPEM;
var
  PrivateKey: TRSAPrivateKey;
  Stream: TStringStream;
begin
  PrivateKey := TRSAPrivateKey.Create;
  try
    Stream := TStringStream.Create(TEST_PRIVATE_KEY, TEncoding.UTF8);
    try
      PrivateKey.LoadFromStream(Stream);
      Assert.IsTrue(PrivateKey.IsValid);
    finally
      Stream.Free;
    end;
  finally
    PrivateKey.Free;
  end;
end;

procedure TOpenSSLRSAUtilsTest.TestLoadCertificate;
var
  Certificate: TX509Cerificate;
  Stream: TStringStream;
begin
  Certificate := TX509Cerificate.Create;
  try
    Stream := TStringStream.Create(TEST_CERTIFICATE, TEncoding.UTF8);
    try
      Certificate.LoadFromStream(Stream);
      Assert.IsTrue(Certificate.IsValid);
    finally
      Stream.Free;
    end;
  finally
    Certificate.Free;
  end;
end;

procedure TOpenSSLRSAUtilsTest.TestPublicKeyFromCertificate;
var
  Certificate: TX509Cerificate;
  PublicKey: TRSAPublicKey;
  Stream: TStringStream;
begin
  Certificate := TX509Cerificate.Create;
  try
    Stream := TStringStream.Create(TEST_CERTIFICATE, TEncoding.UTF8);
    try
      Certificate.LoadFromStream(Stream);
    finally
      Stream.Free;
    end;

    PublicKey := TRSAPublicKey.Create;
    try
      PublicKey.LoadFromCertificate(Certificate);
      Assert.IsTrue(PublicKey.IsValid);
    finally
      PublicKey.Free;
    end;
  finally
    Certificate.Free;
  end;
end;

procedure TOpenSSLRSAUtilsTest.TestGenerateKeyPair;
var
  KeyPair: TRSAKeyPair;
begin
  KeyPair := TRSAKeyPair.Create;
  try
    KeyPair.GenerateKey(1024);  // Use smaller key for faster test
    Assert.IsTrue(KeyPair.PrivateKey.IsValid, 'Generated private key is not valid');
    Assert.IsTrue(KeyPair.PublicKey.IsValid, 'Generated public key is not valid');
  finally
    KeyPair.Free;
  end;
end;

procedure TOpenSSLRSAUtilsTest.TearDown;
begin
  FPublicKeyStream.Free;
  FPrivateKeyStream.Free;
end;

procedure TOpenSSLRSAUtilsTest.TestEncryptDecryptWithPublicPrivateKey;
var
  RSAUtil: TRSAUtil;
  InputStream, EncryptedStream, DecryptedStream: TMemoryStream;
  OriginalText, DecryptedText: string;
  BinaryBuffer: TBytes;
begin
  RSAUtil := TRSAUtil.Create;
  try
    // Load keys
    RSAUtil.PublicKey.LoadFromStream(FPublicKeyStream);
    RSAUtil.PrivateKey.LoadFromStream(FPrivateKeyStream);

    // Prepare test data
    OriginalText := 'Hello OpenSSL!';
    InputStream := TMemoryStream.Create;
    try
      BinaryBuffer := TEncoding.UTF8.GetBytes(OriginalText);
      InputStream.Write(BinaryBuffer[0], Length(OriginalText));
      InputStream.Position := 0;

      // Encrypt
      EncryptedStream := TMemoryStream.Create;
      try
        RSAUtil.PublicEncrypt(InputStream, EncryptedStream);
        Assert.IsTrue(EncryptedStream.Size > 0, 'Encrypted stream is empty');

        // Decrypt
        EncryptedStream.Position := 0;
        DecryptedStream := TMemoryStream.Create;
        try
          RSAUtil.PrivateDecrypt(EncryptedStream, DecryptedStream);
          SetLength(BinaryBuffer, DecryptedStream.Size);
          DecryptedStream.Position := 0;
          DecryptedStream.Read(BinaryBuffer[0], DecryptedStream.Size);
          DecryptedText := TEncoding.UTF8.GetString(BinaryBuffer);
          Assert.AreEqual(OriginalText, DecryptedText, 'Decrypted text does not match original');
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
    RSAUtil.Free;
  end;
end;

procedure TOpenSSLRSAUtilsTest.TestSaveLoadPublicKey;
var
  PublicKey1, PublicKey2: TRSAPublicKey;
  Stream: TMemoryStream;
begin
  PublicKey1 := TRSAPublicKey.Create;
  try
    PublicKey1.LoadFromStream(FPublicKeyStream);

    Stream := TMemoryStream.Create;
    try
      PublicKey1.SaveToStream(Stream);
      Assert.IsTrue(Stream.Size > 0, 'Saved public key stream is empty');

      Stream.Position := 0;
      PublicKey2 := TRSAPublicKey.Create;
      try
        PublicKey2.LoadFromStream(Stream);
        Assert.IsTrue(PublicKey2.IsValid, 'Reloaded public key is not valid');
      finally
        PublicKey2.Free;
      end;
    finally
      Stream.Free;
    end;
  finally
    PublicKey1.Free;
  end;
end;

procedure TOpenSSLRSAUtilsTest.TestSaveLoadPrivateKey;
var
  PrivateKey1, PrivateKey2: TRSAPrivateKey;
  Stream: TMemoryStream;
begin
  PrivateKey1 := TRSAPrivateKey.Create;
  try
    PrivateKey1.LoadFromStream(FPrivateKeyStream);

    Stream := TMemoryStream.Create;
    try
      PrivateKey1.SaveToStream(Stream);
      Assert.IsTrue(Stream.Size > 0, 'Saved private key stream is empty');

      Stream.Position := 0;
      PrivateKey2 := TRSAPrivateKey.Create;
      try
        PrivateKey2.LoadFromStream(Stream);
        Assert.IsTrue(PrivateKey2.IsValid, 'Reloaded private key is not valid');
      finally
        PrivateKey2.Free;
      end;
    finally
      Stream.Free;
    end;
  finally
    PrivateKey1.Free;
  end;
end;

procedure TOpenSSLRSAUtilsTest.TestCertificateSubject;
var
  Certificate: TX509Cerificate;
  Stream: TStringStream;
  Subject: TSubjectInfo;
begin
  Certificate := TX509Cerificate.Create;
  try
    Stream := TStringStream.Create(TEST_CERTIFICATE, TEncoding.UTF8);
    try
      Certificate.LoadFromStream(Stream);
      Subject := Certificate.Subject;

      // TODO: Replace with actual values from the certificate
      Assert.AreEqual('localhost', Subject.CommonName, 'CommonName mismatch');
      Assert.AreEqual('La Mia Azienda', Subject.Organization, 'Organization mismatch');
      Assert.AreEqual('IT Department', Subject.OrganizationalUnit, 'OrganizationalUnit mismatch');
      Assert.AreEqual('IT', Subject.Country, 'Country mismatch');
      Assert.AreEqual('Lombardia', Subject.State, 'State mismatch');
      Assert.AreEqual('Milano', Subject.Locality, 'Locality mismatch');
    finally
      Stream.Free;
    end;
  finally
    Certificate.Free;
  end;
end;

procedure TOpenSSLRSAUtilsTest.TestCertificateIssuer;
var
  Certificate: TX509Cerificate;
  Stream: TStringStream;
  Issuer: TSubjectInfo;
begin
  Certificate := TX509Cerificate.Create;
  try
    Stream := TStringStream.Create(TEST_CERTIFICATE, TEncoding.UTF8);
    try
      Certificate.LoadFromStream(Stream);
      Issuer := Certificate.Issuer;

      // For self-signed certificate, issuer should equal subject
      // TODO: Replace with actual values from the certificate
      Assert.AreEqual('localhost', Issuer.CommonName, 'Issuer CommonName mismatch');
      Assert.AreEqual('La Mia Azienda', Issuer.Organization, 'Issuer Organization mismatch');
      Assert.AreEqual('IT Department', Issuer.OrganizationalUnit, 'Issuer OrganizationalUnit mismatch');
      Assert.AreEqual('IT', Issuer.Country, 'Issuer Country mismatch');
    finally
      Stream.Free;
    end;
  finally
    Certificate.Free;
  end;
end;

procedure TOpenSSLRSAUtilsTest.TestCertificateSerialNumber;
var
  Certificate: TX509Cerificate;
  Stream: TStringStream;
  SerialNumber: TSerialNumber;
  SerialHex: string;
begin
  Certificate := TX509Cerificate.Create;
  try
    Stream := TStringStream.Create(TEST_CERTIFICATE, TEncoding.UTF8);
    try
      Certificate.LoadFromStream(Stream);
      SerialNumber := Certificate.SerialNumber;

      Assert.IsFalse(SerialNumber.IsEmpty, 'Serial number is empty');

      // Get hex representation
      SerialHex := SerialNumber.ToHexString(':');
      Assert.IsTrue(Length(SerialHex) > 0, 'Serial number hex string is empty');

      // Verify it's a valid hex string (should contain digits and A-F)
      Assert.IsTrue(Pos(':', SerialHex) > 0, 'Serial number should contain separator');
    finally
      Stream.Free;
    end;
  finally
    Certificate.Free;
  end;
end;

procedure TOpenSSLRSAUtilsTest.TestCertificateDates;
var
  Certificate: TX509Cerificate;
  Stream: TStringStream;
  NotBefore, NotAfter: TDateTime;
begin
  Certificate := TX509Cerificate.Create;
  try
    Stream := TStringStream.Create(TEST_CERTIFICATE, TEncoding.UTF8);
    try
      Certificate.LoadFromStream(Stream);

      NotBefore := Certificate.NotBefore;
      NotAfter := Certificate.NotAfter;

      Assert.IsTrue(NotBefore > 0, 'NotBefore date is invalid');
      Assert.IsTrue(NotAfter > 0, 'NotAfter date is invalid');
      Assert.IsTrue(NotAfter > NotBefore, 'NotAfter should be after NotBefore');

      // Certificate should be valid for at least 1 day
      Assert.IsTrue(NotAfter - NotBefore >= 1, 'Certificate validity period is too short');
    finally
      Stream.Free;
    end;
  finally
    Certificate.Free;
  end;
end;

procedure TOpenSSLRSAUtilsTest.TestCertificateVersion;
var
  Certificate: TX509Cerificate;
  Stream: TStringStream;
  Version: Integer;
begin
  Certificate := TX509Cerificate.Create;
  try
    Stream := TStringStream.Create(TEST_CERTIFICATE, TEncoding.UTF8);
    try
      Certificate.LoadFromStream(Stream);
      Version := Certificate.Version;

      // Most certificates are v3 (value 3)
      Assert.IsTrue(Version >= 1, 'Version should be at least 1');
      Assert.IsTrue(Version <= 3, 'Version should not exceed 3');
    finally
      Stream.Free;
    end;
  finally
    Certificate.Free;
  end;
end;

procedure TOpenSSLRSAUtilsTest.TestCertificateIsValid;
var
  Certificate: TX509Cerificate;
  Stream: TStringStream;
  FutureDate, PastDate: TDateTime;
begin
  Certificate := TX509Cerificate.Create;
  try
    Stream := TStringStream.Create(TEST_CERTIFICATE, TEncoding.UTF8);
    try
      Certificate.LoadFromStream(Stream);

      // Test current validity
      Assert.IsTrue(Certificate.IsValidNow, 'Certificate should be valid now');
      Assert.IsFalse(Certificate.IsExpired, 'Certificate should not be expired');

      // Test validity at specific dates
      PastDate := EncodeDate(2020, 1, 1);
      Assert.IsFalse(Certificate.IsValidAt(PastDate), 'Certificate should not be valid in 2020');

      FutureDate := EncodeDate(2040, 1, 1);
      Assert.IsFalse(Certificate.IsValidAt(FutureDate), 'Certificate should not be valid in 2040');
    finally
      Stream.Free;
    end;
  finally
    Certificate.Free;
  end;
end;

procedure TOpenSSLRSAUtilsTest.TestCertificateDaysUntilExpiration;
var
  Certificate: TX509Cerificate;
  Stream: TStringStream;
  Days: Integer;
begin
  Certificate := TX509Cerificate.Create;
  try
    Stream := TStringStream.Create(TEST_CERTIFICATE, TEncoding.UTF8);
    try
      Certificate.LoadFromStream(Stream);
      Days := Certificate.DaysUntilExpiration;

      // Certificate should have positive days remaining (not expired)
      Assert.IsTrue(Days > 0, 'Certificate should have days remaining until expiration');

      // Should have a reasonable number of days (less than 20 years)
      Assert.IsTrue(Days < 365 * 20, 'Days until expiration seems unreasonably high');
    finally
      Stream.Free;
    end;
  finally
    Certificate.Free;
  end;
end;

procedure TOpenSSLRSAUtilsTest.TestPrintCertificateInfo;
var
  Certificate: TX509Cerificate;
  Stream: TStringStream;
  Info: string;
begin
  Certificate := TX509Cerificate.Create;
  try
    Stream := TStringStream.Create(TEST_CERTIFICATE, TEncoding.UTF8);
    try
      Certificate.LoadFromStream(Stream);
      Info := Certificate.PrintCertificateInfo;

      Assert.IsTrue(Length(Info) > 0, 'Certificate info should not be empty');

      // Verify it contains expected sections
      Assert.IsTrue(Pos('Subject:', Info) > 0, 'Info should contain Subject');
      Assert.IsTrue(Pos('Issuer:', Info) > 0, 'Info should contain Issuer');
      Assert.IsTrue(Pos('Serial Number:', Info) > 0, 'Info should contain Serial Number');
      Assert.IsTrue(Pos('Version:', Info) > 0, 'Info should contain Version');
      Assert.IsTrue(Pos('Validity:', Info) > 0, 'Info should contain Validity section');
      Assert.IsTrue(Pos('Not Before:', Info) > 0, 'Info should contain Not Before date');
      Assert.IsTrue(Pos('Not After:', Info) > 0, 'Info should contain Not After date');
    finally
      Stream.Free;
    end;
  finally
    Certificate.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TOpenSSLRSAUtilsTest);

end.
