# Delphi OpenSSL Library

[Delphi](http://www.embarcadero.com/products/delphi) wrapper for [OpenSSL](https://openssl.org/).

## Features

- Encrypt/Decrypt using RSA algorithm
- Symmetric cipher routines
- Base64 encoding e decoding
- Basic PAM support
- Generation of pseudo-random bit strings
- Basic SMIME support
- Generate RSA KeyPairs in PKCS PEM format

## Usage

### Encrypt with the public key inside X509 certificate

*Command line:*

    OpenSSL rsautl -encrypt -certin -inkey publiccert.cer -in test.txt -out test.txt.cry


*Source code:*

```delphi
var
  RSAUtil :TRSAUtil;
  Cerificate :TX509Cerificate;
begin
  RSAUtil := TRSAUtil.Create;
  try
    Cerificate := TX509Cerificate.Create;
    try
      Cerificate.LoadFromFile('publiccert.cer');
      RSAUtil.PublicKey.LoadFromCertificate(Cerificate);
      RSAUtil.PublicEncrypt('test.txt', 'test.txt.cry');
    finally
      Cerificate.Free;
    end;
  finally
    RSAUtil.Free;
  end;
end;
```

### Encrypt with the public key in PEM format

*Command line:*

    OpenSSL rsautl -encrypt -pubin -inkey publickey.pem -in test.txt -out test.txt.cry

*Source code:*

```delphi
var
  RSAUtil :TRSAUtil;
begin
  RSAUtil := TRSAUtil.Create;
  try
    RSAUtil.PublicKey.LoadFromFile('publickey.pem');
    RSAUtil.PublicEncrypt('test.txt', 'test.txt.cry');
  finally
    RSAUtil.Free;
  end;
end;
```

### Decrypt with the private key in PEM format

*Command line:*

    OpenSSL rsautl -decrypt -inkey privatekey.pem -in test.txt.cry -out test.txt


*Source code:*

```delphi
var
  RSAUtil :TRSAUtil;
begin
  RSAUtil := TRSAUtil.Create;
  try
    RSAUtil.PrivateKey.OnNeedPassphrase := PassphraseReader;
    RSAUtil.PrivateKey.LoadFromFile('privatekey.pem');
    RSAUtil.PrivateDecrypt('test.txt.cry', 'test.txt');
  finally
    RSAUtil.Free;
  end;
end;
```

### Encrypt with AES256

*Command line:*

    OpenSSL enc -base64 -aes256 -in text.plain -out text.aes256 -k secure


*Source code:*

```delphi
var
  EncUtil :TEncUtil;
begin
  EncUtil := TEncUtil.Create;
  try
    EncUtil.UseBase64 := True;
    EncUtil.Passphrase := 'secure';
    EncUtil.Cipher := 'AES-256';
    EncUtil.Encrypt('text.plain', 'text.aes256');
  finally
    EncUtil.Free;
  end;
end;
```


## Todo

- Symmetric cryptography (partially done)
- compute hash functions
- Sign e verify
- RSA data management
- Data managing for X509
- Manage information according to the PKCS #12 standard

## Prerequisite

OpenSSL library must be in your system path

## Installation

- Add the source path "Source" to your Delphi project path
- Run the demo and follow the tutorial
