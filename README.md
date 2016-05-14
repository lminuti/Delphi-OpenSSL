# Delphi OpenSSL Library

[Delphi](http://www.embarcadero.com/products/delphi) implementation of OpenSSL.

## Features

### Encrypt/Decrypt files using RSAUtl module of OpenSSL

Delphi OpenSSL offers an API to Encrypt/Decrypt

    OpenSSL rsautl -encrypt -certin -inkey publiccert.pem -in test.txt -out test.txt.cry
    OpenSSL rsautl -encrypt -pubin -inkey publickey.pem -in test.txt -out test.txt.cry
    OpenSSL rsautl -decrypt -inkey privatekey.pem -in test.txt.cry -out test.txt

## Todo

- Read certificate from a buffer
- Sign e verify
- Symmetric cryptography

## Prerequisite
OpenSSL library must be in your system path

## Installation
- Add the source path "Source" to your Delphi project path
- Run the demo and follow the tutorial

