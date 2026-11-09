# Random bytes, Base64, S/MIME, errors, raw API

## TRandUtil (`OpenSSL.RandUtils`)

All class methods; it does **not** load libcrypto itself, so make sure `LoadOpenSSLLibrary` was called (or another crypto object was created) first.

```delphi
LKey := TRandUtil.GetRandomBytes(32);          // RAND_bytes, cryptographically secure
LNonce := TRandUtil.GetPseudoRandomBytes(12);  // also RAND_bytes today
TRandUtil.Initialized;                         // RAND_status
TRandUtil.InitPool;                            // RAND_poll — not needed on modern OpenSSL
TRandUtil.LoadSeedFromFile(TRandUtil.GetDefaultSeedFileName);
TRandUtil.SaveSeedToFile(TRandUtil.GetDefaultSeedFileName);
```

Do not use `System.Random` for keys, IVs, salts or tokens.

## Base64 (`OpenSSL.Core`)

```delphi
function Base64Encode(InputBuffer: TBytes): TBytes;
function Base64Decode(InputBuffer: TBytes): TBytes;

LText := TEncoding.ASCII.GetString(Base64Encode(LData));
LData := Base64Decode(TEncoding.ASCII.GetBytes(LText));
```

Uses the OpenSSL BIO Base64 filter without `BIO_FLAGS_BASE64_NO_NL`: output has a line break every 64 chars plus a trailing newline, exactly like `openssl base64`. For the same reason decoding expects that layout: Base64 coming from other sources as a single long line (JSON, HTTP headers) may decode to nothing — for those use `System.NetEncoding.TNetEncoding.Base64` instead.

## TSMIMEUtil (`OpenSSL.SMIMEUtils`)

```delphi
function Decrypt(InputStream, OutputStream: TStream; Verify, NoVerify: Boolean): Integer;
```

Despite the name it handles **signed** PKCS#7 in **DER** form (e.g. `.p7m` files): it parses the PKCS#7 and, if `Verify = True`, runs `PKCS7_verify` writing the signed content to `OutputStream`. `NoVerify = True` skips certificate chain verification (there is no trust store configured, so pass `True` unless you know what you are doing). Returns 1 on success, 0 on failure. Enveloped (encrypted) S/MIME is not decrypted.

```delphi
// extract the document from a signed .p7m
LIn := TFileStream.Create('document.pdf.p7m', fmOpenRead);
LOut := TFileStream.Create('document.pdf', fmCreate);
LSMIME := TSMIMEUtil.Create;
try
  if LSMIME.Decrypt(LIn, LOut, True, True) <> 1 then
    raise Exception.Create('Invalid PKCS#7 signature');
finally
  LSMIME.Free; LOut.Free; LIn.Free;
end;
```

For Base64/PEM `.p7m` decode to DER first (`Base64Decode`).

## Errors (`OpenSSL.Core`)

- `EOpenSSLError` — base class; `EOpenSSLLibError` adds `ErrorCode`.
- `RaiseOpenSSLError(const AMessage: string = '')` — raises with the last OpenSSL error queue message appended; use it after a failing raw API call.
- `GetOpenSSLErrorMessage: string` — pops the last error from the OpenSSL queue.

```delphi
try
  LRSAUtil.PrivateKey.LoadFromFile('key.pem');
except
  on E: EOpenSSLError do
    Log('OpenSSL error: ' + E.Message);   // e.g. wrong passphrase, bad PEM
end;
```

## Dropping to the raw C API (`OpenSSL.Api`)

When the high-level classes do not cover a need, the C functions are available as procedural variables in `OpenSSL.Api` (resolved at runtime by `TOpenSSLLoader`).

- Ensure the library is loaded first (`LoadOpenSSLLibrary`).
- Optional/version-specific symbols may be `nil`: test with `Assigned(...)` or check `GetOpenSSLLoader.VersionNum` before calling.
- Use the helpers in `OpenSSL.Core` (`BIO_new_mem_buf(TBytes)`, `BIO_read(b, var TBytes)`, `BIO_to_string`, `BIO_get_mem_data`) instead of reimplementing BIO macros.
- Raw keys from the high-level classes are available via `.RSA` (`PRSA`, owned by the object — do not free it); `TRSAPublicKey.CreateFromRSA` / `TRSAPrivateKey.CreateFromRSA` wrap a raw key back.
- Always free what you allocate (`EVP_PKEY_free`, `BIO_free`, `X509_free`, ...) in `try..finally`.
