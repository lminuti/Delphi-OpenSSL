# RSA: keys, encryption, signatures (`OpenSSL.RSAUtils`)

## Key classes

- `TRSAPublicKey` / `TRSAPrivateKey` (base types `TCustomRSAPublicKey` / `TCustomRSAPrivateKey`)
  - `LoadFromFile(FileName, AFormat)`, `LoadFromStream(Stream, AFormat)`
  - `SaveToFile(FileName, AFormat)`, `SaveToStream(Stream, AFormat)`
  - `IsValid: Boolean`, `Print: string` (textual dump), `RSA: PRSA` (raw handle, owned by the object)
  - `TRSAPublicKey.LoadFromCertificate(Cert: TX509Certificate)`
  - `CreateFromRSA(ARSA: PRSA)` — wraps an existing raw key
- Formats (PEM only):
  - Public: `kfDefault` = `-----BEGIN PUBLIC KEY-----` (SubjectPublicKeyInfo); `kfRSAPublicKey` = `-----BEGIN RSA PUBLIC KEY-----` (PKCS#1)
  - Private: `kpDefault` = `-----BEGIN PRIVATE KEY-----` / any format `PEM_read_bio_PrivateKey` accepts (also encrypted); `kpRSAPrivateKey` = `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1)
- Saved private keys are **not encrypted**.

## Encrypted private keys: passphrase callback

```delphi
procedure TMainForm.PassphraseReader(Sender: TObject; var Passphrase: string);
begin
  Passphrase := EditPassword.Text;   // will be sent to OpenSSL as UTF-8
end;
...
RSAUtil.PrivateKey.OnNeedPassphrase := PassphraseReader;  // set BEFORE LoadFromFile
RSAUtil.PrivateKey.LoadFromFile('privatekey.pem');
```

`TPassphraseEvent = procedure(Sender: TObject; var Passphrase: string) of object` — a method, not an anonymous procedure.

## TRSAUtil

```delphi
procedure PublicEncrypt(InStream, OutStream: TStream; Padding: TRASPadding = rpPKCS); overload;
procedure PublicEncrypt(const InFile, OutFile: TFileName; Padding: TRASPadding = rpPKCS); overload;
procedure PrivateDecrypt(InStream, OutStream: TStream; Padding: TRASPadding = rpPKCS); overload;
procedure PrivateDecrypt(const InFile, OutFile: TFileName; Padding: TRASPadding = rpPKCS); overload;
procedure Sign(MsgStream, SignStream: TStream); overload;               // SHA-256, PKCS#1 v1.5
procedure Sign(const MsgFile, SignFile: TFileName); overload;
function  Verify(MsgStream, SignStream: TStream): Boolean; overload;
function  Verify(const MsgFile, SignFile: TFileName): Boolean; overload;
property PublicKey: TCustomRSAPublicKey;
property PrivateKey: TCustomRSAPrivateKey;
```

Important constraints:
- **Encryption is a single RSA block**: the whole input stream is encrypted with one `RSA_public_encrypt` call. Max plaintext = key size in bytes − 11 (PKCS#1 v1.5, e.g. 245 bytes for 2048-bit) or − 42 (OAEP, 214 bytes). For larger data use hybrid encryption: random AES key via `TRandUtil`, data with `TEncUtil`, AES key with `PublicEncrypt` (example below).
- Ciphertext length = key size in bytes (256 for 2048-bit).
- Encrypt and decrypt with the **same** `TRASPadding` (`rpPKCS` default, `rpOAEP` recommended for new designs; `rpSSL` / `rpRAW` are legacy).
- Input streams are read with `ReadBuffer(..., Stream.Size)` from the **current position**: if `Position` is not 0 the call fails with `EReadError`. Always set `Position := 0` on a stream you have just written to before passing it in. Output is appended at the output stream's current position. The same applies to `TEncUtil` and `TSMIMEUtil`.
- `Sign`/`Verify` are SHA-256 with PKCS#1 v1.5 padding, interoperable with `openssl dgst -sha256 -sign key.pem` / `-verify pub.pem -signature sig.bin`.

## Examples

### Encrypt with a certificate, decrypt with the private key

```delphi
uses OpenSSL.Core, OpenSSL.RSAUtils;

var
  LRSAUtil: TRSAUtil;
  LCert: TX509Certificate;
begin
  LRSAUtil := TRSAUtil.Create;
  try
    LCert := TX509Certificate.Create;
    try
      LCert.LoadFromFile('publiccert.pem');
      LRSAUtil.PublicKey.LoadFromCertificate(LCert);
    finally
      LCert.Free;
    end;
    LRSAUtil.PublicEncrypt('secret.txt', 'secret.txt.cry', rpOAEP);

    LRSAUtil.PrivateKey.LoadFromFile('privatekey.pem');
    LRSAUtil.PrivateDecrypt('secret.txt.cry', 'secret.out.txt', rpOAEP);
  finally
    LRSAUtil.Free;
  end;
end;
```

### Sign and verify in memory

```delphi
function SignBytes(const AData: TBytes; const APrivKeyFile: string): TBytes;
var
  LRSAUtil: TRSAUtil;
  LMsg, LSig: TBytesStream;
begin
  LRSAUtil := TRSAUtil.Create;
  LMsg := TBytesStream.Create(AData);
  LSig := TBytesStream.Create;
  try
    LRSAUtil.PrivateKey.LoadFromFile(APrivKeyFile);
    LRSAUtil.Sign(LMsg, LSig);
    Result := Copy(LSig.Bytes, 0, LSig.Size);
  finally
    LSig.Free;
    LMsg.Free;
    LRSAUtil.Free;
  end;
end;

function VerifyBytes(const AData, ASignature: TBytes; const APubKeyFile: string): Boolean;
var
  LRSAUtil: TRSAUtil;
  LMsg, LSig: TBytesStream;
begin
  LRSAUtil := TRSAUtil.Create;
  LMsg := TBytesStream.Create(AData);
  LSig := TBytesStream.Create(ASignature);
  try
    LRSAUtil.PublicKey.LoadFromFile(APubKeyFile);
    Result := LRSAUtil.Verify(LMsg, LSig);
  finally
    LSig.Free;
    LMsg.Free;
    LRSAUtil.Free;
  end;
end;
```

### Generate and save a key pair

```delphi
var
  LKeyPair: TRSAKeyPair;
begin
  LKeyPair := TRSAKeyPair.Create;
  try
    LKeyPair.GenerateKey(3072);                      // GenerateKey without args = 2048 bit
    LKeyPair.PrivateKey.SaveToFile('private.pem');   // unencrypted PKCS#8 PEM
    LKeyPair.PublicKey.SaveToFile('public.pem');     // SubjectPublicKeyInfo PEM
    LKeyPair.PublicKey.SaveToFile('public-rsa.pem', kfRSAPublicKey);  // PKCS#1
  finally
    LKeyPair.Free;
  end;
end;
```

### Use a generated pair directly with TRSAUtil (shared key objects)

```delphi
LKeyPair := TRSAKeyPair.Create;
LRSAUtil := TRSAUtil.Create;
try
  LKeyPair.GenerateKey;
  LRSAUtil.PublicKey := LKeyPair.PublicKey;    // not owned by TRSAUtil
  LRSAUtil.PrivateKey := LKeyPair.PrivateKey;
  ...
finally
  LRSAUtil.Free;   // free the util first
  LKeyPair.Free;   // then the owner of the keys
end;
```

### Hybrid encryption for large data

```delphi
// sender
LAesKey := TRandUtil.GetRandomBytes(32);
LIV     := TRandUtil.GetRandomBytes(16);
LEncUtil.Cipher := 'AES-256-CBC';
LEncUtil.Passphrase := TPassphrase.Create(LAesKey, LIV);
LEncUtil.Encrypt(LPlainBytes, LCipherBytes);
// encrypt LAesKey + LIV (48 bytes) with LRSAUtil.PublicEncrypt(..., rpOAEP)
// and transmit both the RSA block and LCipherBytes
```
