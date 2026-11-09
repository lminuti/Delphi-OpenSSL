# Symmetric encryption (`OpenSSL.EncUtils`)

## TEncUtil

```delphi
property Cipher: TCipherName;        // e.g. 'AES-256'; unknown name raises EOpenSSLError
property Passphrase: TPassphrase;    // password or explicit key+IV
property UseBase64: Boolean;         // Base64 on top of the binary output (Encrypt/Decrypt overloads)

procedure Encrypt(InStream, OutStream: TStream); overload;
procedure Encrypt(const InFile, OutFile: TFileName); overload;
procedure Encrypt(const InBytes: TBytes; out OutBytes: TBytes); overload;
function  EncryptStr(const S: string; Encoding: TEncoding = nil): string;  // returns Base64
procedure Decrypt(...);              // same overloads
function  DecryptStr(const S: string; Encoding: TEncoding = nil): string;  // expects Base64

class procedure SupportedCiphers(Ciphers: TStrings);
class procedure RegisterCipher(const Name: TCipherName; Proc: TCipherProc);
class procedure GenerateKeyIV(const APassword: string; Cipher: TCipherName; Salt: TBytes; var Key, IV: TBytes);
```

`EncryptStr`/`DecryptStr` encode the text with `Encoding` (default UTF-8) and **always** Base64 the ciphertext, independently of `UseBase64`.

## Cipher names

Names are case-sensitive as registered: `AES` / `AES-256` / `AES-CBC` / `AES-256-CBC` (all AES-256-CBC), `AES-128`, `AES-192`, `AES-128-CBC`, ..., and modes `-CFB`, `-CFB1`, `-CFB8`, `-ECB`, `-OFB` with optional key size (`AES-128-OFB`). If `Cipher` is never set the default is AES-256-CBC.

Legacy names (`BF*`, `DES*`, `DES3`, `DESX`, `IDEA*`, `RC2*`, `RC4*`) are registered only if the loaded libcrypto exports them — normally only OpenSSL 1.0/1.1. Call `TEncUtil.SupportedCiphers(List)` to see what is available at runtime.

No AEAD modes (GCM/CCM/ChaCha20-Poly1305) are exposed: output is **not authenticated**. If integrity matters, sign the ciphertext (`TRSAUtil.Sign`) or add an HMAC outside the library.

## Passphrase modes

```delphi
LEncUtil.Passphrase := 'my password';                         // implicit: UTF-8 password
LEncUtil.Passphrase := TPassphrase.Create('pwd', TEncoding.ANSI); // password in another encoding
LEncUtil.Passphrase := LPasswordBytes;                        // implicit TBytes = raw password bytes (NOT a key)
LEncUtil.Passphrase := TPassphrase.Create(LKey, LIV);         // explicit key + IV
```

- **Password mode**: a random 8-byte salt is generated; key/IV are derived with `EVP_BytesToKey(MD5, 1 iteration)`; output is `"Salted__" + salt + ciphertext` (OpenSSL `enc` format). Encrypting twice gives different outputs.
- **Key mode**: no salt/header; output is the raw ciphertext. Key length must match the cipher (32 bytes for AES-256), IV length must equal the cipher IV length (16 for AES CBC/CFB/OFB) or `EOpenSSLError('Invalid IV length for cipher')` is raised; for ECB the IV is ignored.
- No passphrase at all → `EOpenSSLError('Password needed')`.

## Command-line interoperability

```
openssl enc -aes-256-cbc -md md5 -a -k secure -in plain.txt -out plain.aes   # = UseBase64 + Passphrase 'secure'
openssl enc -d -aes-256-cbc -md md5 -a -k secure -in plain.aes
```

`-md md5` is required with OpenSSL ≥ 1.1 (its default digest is SHA-256); `-pbkdf2` / `-iter` output is **not** compatible. With explicit keys use `-K <hexkey> -iv <hexiv> -nosalt`.

## Examples

```delphi
// files, OpenSSL-compatible Base64 output
LEncUtil := TEncUtil.Create;
try
  LEncUtil.UseBase64 := True;
  LEncUtil.Passphrase := 'secure';
  LEncUtil.Cipher := 'AES-256';
  LEncUtil.Encrypt('text.plain', 'text.aes256');
  LEncUtil.Decrypt('text.aes256', 'text.out');
finally
  LEncUtil.Free;
end;

// explicit random key (store LKey/LIV securely)
LKey := TRandUtil.GetRandomBytes(32);
LIV  := TRandUtil.GetRandomBytes(16);
LEncUtil.Cipher := 'AES-256-CBC';
LEncUtil.Passphrase := TPassphrase.Create(LKey, LIV);
LEncUtil.Encrypt(LPlain, LCipher);
LEncUtil.Decrypt(LCipher, LPlainAgain);

// derive the same key/IV the password mode would use
TEncUtil.GenerateKeyIV('secure', 'AES-256', LSalt, LKey, LIV);
```

Whole input is loaded into memory (no streaming in chunks): keep that in mind for very large files.
