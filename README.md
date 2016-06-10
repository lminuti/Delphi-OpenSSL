# Delphi OpenSSL Library

[Delphi](http://www.embarcadero.com/products/delphi) implementation of [OpenSSL](https://openssl.org/).

## Features

- Encrypt/Decrypt using RSA algorithm
- Symmetric cipher routines (for now only AES256)
- Base64 encoding e decoding
- Basic PAM support

## Usage

### Encrypt with the public key inside X509 certificate

*Command line:*

    OpenSSL rsautl -encrypt -certin -inkey publiccert.cer -in test.txt -out test.txt.cry


*Source code:*

```
#!delphi
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

```
#!delphi
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

```
#!delphi
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


## Todo

- Symmetric cryptography (partially done)
- compute hash functions
- Sign e verify
- Generation of pseudo-random bit strings
- RSA data management
- Data managing for X509
- Manage information according to the PKCS #12 standard

## Prerequisite

OpenSSL library must be in your system path

## Installation

- Add the source path "Source" to your Delphi project path
- Run the demo and follow the tutorial
