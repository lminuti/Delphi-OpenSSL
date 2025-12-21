# Delphi OpenSSL Library

A [Delphi](http://www.embarcadero.com/products/delphi) wrapper for [OpenSSL](https://openssl.org/), providing high-level object-oriented interfaces for cryptographic operations. This library simplifies the use of OpenSSL's powerful encryption capabilities in Delphi applications, offering easy-to-use classes for RSA encryption, symmetric ciphers, digital signatures, and certificate handling.

## Features

- Encrypt/Decrypt using RSA algorithm
- Symmetric cipher routines
- Base64 encoding e decoding
- Basic PAM support
- Generation of pseudo-random bit strings
- Basic SMIME support
- Generate RSA KeyPairs in PKCS PEM format
- Generate self-signed X.509 certificates and Certificate Signing Requests (CSR)

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

### Generate a self-signed certificate

*Command line:*

    OpenSSL req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes


*Source code:*

```delphi
var
  ReqUtil: TReqUtil;
begin
  ReqUtil := TReqUtil.Create;
  try
    ReqUtil.GenerateSelfSignedCertificate('CN=localhost,O=MyCompany,C=IT', 365, 2048);
    ReqUtil.SaveCertificateToFile('cert.pem');
    ReqUtil.SavePrivateKeyToFile('key.pem');
  finally
    ReqUtil.Free;
  end;
end;
```

### Generate a Certificate Signing Request (CSR)

*Command line:*

    OpenSSL req -new -newkey rsa:2048 -keyout key.pem -out request.csr -nodes


*Source code:*

```delphi
var
  ReqUtil: TReqUtil;
begin
  ReqUtil := TReqUtil.Create;
  try
    ReqUtil.GenerateCSR('CN=example.com,O=MyCompany,C=IT', 2048);
    ReqUtil.SaveCSRToFile('request.csr');
    ReqUtil.SavePrivateKeyToFile('key.pem');
  finally
    ReqUtil.Free;
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

### Installing OpenSSL

If your application requires OpenSSL support, you must have the necessary library files in your file system before deploying your application.

| Platform | Download Required | File Names | Static/Dynamic Linking |
|----------|------------------|------------|----------------------|
| Windows (32-bit and 64-bit) | Yes | libeay32.dll and ssleay32.dll | Dynamic |
| iOS Device | Yes | libcrypto.a and libssl.a | Static |
| Android Device | No | | Dynamic |

Review the requirements below depending on the platform that you are using:

#### 32-bit and 64-bit Windows

To install OpenSSL on 32-bit or 64-bit Windows, you need to copy the **libeay32.dll** and **ssleay32.dll** dynamic library files to your file system; you can download them from one of these locations:

- **Option 1** - Download the [OpenSSL installer files](http://slproweb.com/products/Win32OpenSSL.html) and install them.
- **Option 2** - Download the [OpenSSL compressed library files](https://github.com/IndySockets/OpenSSL-Binaries) and copy the libeay32.dll and ssleay32.dll files to your system path.

If you go for Option 2 and decide to copy libeay32.dll and ssleay32.dll files to your system path, ensure you copy them to the right location:

- **32-bit Windows**: You must copy the libeay32.dll and ssleay32.dll 32-bit files to your Windows system folder (System32 folder).
- **64-bit Windows**: You must copy the libeay32.dll and ssleay32.dll 64-bit files to your Windows system folder for 64-bit files (System32) and the libeay32.dll and ssleay32.dll 32-bit files to your Windows 32-bit files folder (SysWOW64 folder).

So when working with a 64-bit Windows, remember:
- **System32 folder** is for 64-bit files only.
- **SysWOW64 folder** is for 32-bit files only.

## Installation

- Add the source path "Source" to your Delphi project path
- Run the demo and follow the tutorial
