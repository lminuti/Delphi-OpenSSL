# Delphi OpenSSL Library

<br />
<p align="center">
  <img src="DelphiOpenSSL.png" alt="Delphi OpenSSL" width="200" />
</p>


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
- Support for OpenSSL 1.0.x, 1.1.x, 3.x and 4.x from a single build, with the library selected at runtime
- No external component dependency (no Indy/TaurusTLS): the OpenSSL C API is bound directly

## Usage

### Encrypt with the public key inside X509 certificate

*Command line:*

    OpenSSL rsautl -encrypt -certin -inkey publiccert.cer -in test.txt -out test.txt.cry


*Source code:*

```delphi
var
  RSAUtil :TRSAUtil;
  Certificate :TX509Certificate;
begin
  RSAUtil := TRSAUtil.Create;
  try
    Certificate := TX509Certificate.Create;
    try
      Certificate.LoadFromFile('publiccert.cer');
      RSAUtil.PublicKey.LoadFromCertificate(Certificate);
      RSAUtil.PublicEncrypt('test.txt', 'test.txt.cry');
    finally
      Certificate.Free;
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


## Core Units

| Unit | Purpose |
|------|---------|
| `OpenSSL.Api.pas` | Low-level OpenSSL C API (types, constants and function prototypes) and the runtime loader for `libcrypto` (`SSLLibVersions`, `OpenSSLPath`, version selection) |
| `OpenSSL.Core.pas` | Base classes, error handling, `TSubjectInfo`/`TSerialNumber` records, utility functions (Base64, EVP helpers) |
| `OpenSSL.RSAUtils.pas` | RSA operations: `TRSAUtil`, `TRSAPublicKey`, `TRSAPrivateKey`, `TX509Certificate`, `TRSAKeyPair` |
| `OpenSSL.EncUtils.pas` | Symmetric encryption: `TEncUtil` with cipher support (AES, etc.) |
| `OpenSSL.RandUtils.pas` | Random number generation: `TRandUtil` |
| `OpenSSL.ReqUtils.pas` | Certificate/CSR generation: `TReqUtil` |
| `OpenSSL.SMIMEUtils.pas` | S/MIME support: `TSMIMEUtil` |

## Prerequisite

### Installing OpenSSL

The library only loads the `libcrypto` shared library, selected at runtime. You must have the matching file for the OpenSSL version you want to use available on your file system (or point the loader at it).

| OpenSSL | Windows | Linux |
|---------|---------|-------|
| 4.x | `libcrypto-4.dll` | `libcrypto.so.4` |
| 3.x | `libcrypto-3.dll` | `libcrypto.so.3` |
| 1.1.x | `libcrypto-1_1.dll` | `libcrypto.so.1.1` |
| 1.0.x | `libeay32.dll` | `libcrypto.so.1.0.0` |

`libssl` is not required.

On 64-bit Windows the library files use the `-x64` suffix (`libcrypto-4-x64.dll`, `libcrypto-3-x64.dll`, `libcrypto-1_1-x64.dll`); the loader picks the right names based on the target platform. OpenSSL 1.0.x on Windows is `libeay32.dll` for both 32- and 64-bit.

#### 32-bit and 64-bit Windows

Copy the `libcrypto` file for the target OpenSSL version to your application folder, to a directory on the `PATH`, or to the directory configured through `OpenSSLPath` (see below). Builds are available from:

- **Option 1** - Download the [OpenSSL installer files](http://slproweb.com/products/Win32OpenSSL.html) and install them.
- **Option 2** - Download the [OpenSSL compressed library files](https://github.com/IndySockets/OpenSSL-Binaries) and copy the `libcrypto` file to your system path.

So when working with a 64-bit Windows, remember:
- **System32 folder** is for 64-bit files only.
- **SysWOW64 folder** is for 32-bit files only.

## Installation

- Add the source path "Source" to your Delphi project path
- Run the demo and follow the tutorial

## Selecting the OpenSSL version

A single build supports OpenSSL 1.0.x, 1.1.x, 3.x and 4.x. The loader (`OpenSSL.Api.pas`) tries the entries of `SSLLibVersions` in order and loads the first library found; the OpenSSL version is then detected at runtime and the matching entry points are used. No `libssl` DLL is needed.

```delphi
uses
  OpenSSL.Core, OpenSSL.Api;

// Choose a specific library (or a fallback list) on the loader singleton
GetOpenSSLLoader.SSLLibVersions := 'libcrypto-1_1';   // try only this one (Windows)
// GetOpenSSLLoader.SSLLibVersions := 'libcrypto-3;libcrypto-1_1;libeay32';

// or pass the list directly when loading (overrides the loader setting)
if not LoadOpenSSLLibrary('libcrypto-3') then
  raise EOpenSSLError.Create('Cannot open OpenSSL');

// Optional: directory where the library is searched
GetOpenSSLLoader.OpenSSLPath := 'C:\OpenSSL\bin';
```

- `LoadOpenSSLLibrary(const ASSLLibVersions: string = '')` accepts an optional list of library names; when non-empty it overrides the loader setting for that call. When omitted (or empty), the loader keeps its current `SSLLibVersions` (default list unless changed).
- `SSLLibVersions` is a `;`-separated list of library file names. Defaults: Windows 32-bit `libcrypto-4;libcrypto-3;libcrypto-1_1;libeay32`, Windows 64-bit `libcrypto-4-x64;libcrypto-3-x64;libcrypto-1_1-x64;libeay32`, Linux `libcrypto.so.4;libcrypto.so.3;libcrypto.so.1.1;libcrypto.so.1.0.0`.
- `OpenSSLPath` (or the `OPENSSL_LIBRARY_PATH` environment variable) sets the search directory; empty means the system search path.
- Symbols that are not available in the loaded version stay `nil` and are listed in `GetOpenSSLLoader.FailedToLoad`; legacy ciphers removed from OpenSSL 3.x/4.x are simply not registered.
