# Certificates, CSRs and subject names

## TSubjectInfo (`OpenSSL.Core`)

Record with `CommonName`, `Organization`, `OrganizationalUnit`, `Country`, `State`, `Locality`, `EmailAddress`.

```delphi
LSubject := '/C=IT/ST=Lombardia/L=Milano/O=MyOrg/OU=IT/CN=www.example.com';   // implicit, '/'-delimited
LSubject := TSubjectInfo.Create('CN=www.example.com,O=MyOrg,C=IT', ',');       // other delimiters
LSubject.CommonName := 'localhost';                                            // or set fields one by one
LText := LSubject;                                                             // back to '/CN=.../O=...'
```

Keys recognised when parsing: `CN`, `O`, `OU`, `C`, `ST`, `L`, `EMAIL` / `EMAILADDRESS`. Unknown keys are ignored. **Do not** pass a comma-separated string through the implicit conversion: it only splits on `/`, so `'CN=a,O=b'` becomes `CommonName = 'a,O=b'`. Values cannot contain the delimiter.

## TSerialNumber (`OpenSSL.Core`)

Implicit conversions to/from `string` (hex), `Int64`, `TBytes`. Methods: `ToHexString(Separator: Char = #0)` (e.g. `ToHexString(':')`), `ToInt64` (raises if > 8 bytes), `TryToInt64`, `IsEmpty`, `Data`.

## TX509Certificate (`OpenSSL.RSAUtils`)

```delphi
procedure LoadFromFile(const FileName: string);    // PEM only
procedure LoadFromStream(AStream: TStream);
function  IsValid: Boolean;                        // a certificate is loaded
function  Print: string;                           // like `openssl x509 -text`
function  PrintCertificateInfo: string;            // short human-readable summary
function  IsExpired: Boolean;
function  IsValidNow: Boolean;                     // NotBefore <= now <= NotAfter
function  IsValidAt(ADateTime: TDateTime): Boolean;
function  DaysUntilExpiration: Integer;
property Subject, Issuer: TSubjectInfo;
property SerialNumber: TSerialNumber;
property NotBefore, NotAfter: TDateTime;
property Version: Integer;                         // 1..3 (human version, not the 0-based field)
```

`TX509Cerificate` is a deprecated alias kept for old code. `IsValidNow` checks only the dates — there is **no chain/trust/revocation validation** in this class.

```delphi
LCert := TX509Certificate.Create;
try
  LCert.LoadFromFile('server.pem');
  Writeln('Subject : ', string(LCert.Subject));
  Writeln('Issuer  : ', LCert.Issuer.CommonName);
  Writeln('Serial  : ', LCert.SerialNumber.ToHexString(':'));
  Writeln('Expires : ', DateTimeToStr(LCert.NotAfter), ' (', LCert.DaysUntilExpiration, ' days)');
  if LCert.IsExpired then
    Writeln('EXPIRED');
finally
  LCert.Free;
end;
```

DER (`.cer` binary) certificates are not supported: convert with `openssl x509 -inform DER -in a.cer -out a.pem` or wrap the Base64 of the DER bytes between `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----` lines before loading.

## TReqUtil (`OpenSSL.ReqUtils`)

```delphi
procedure GenerateSelfSignedCertificate(const Subject: TSubjectInfo; ValidDays: Integer = 365; KeySize: Integer = 2048);
procedure GenerateCSR(const Subject: TSubjectInfo; KeySize: Integer = 2048);
procedure SaveCertificateToFile/Stream(...);   // PEM, after GenerateSelfSignedCertificate
procedure SaveCSRToFile/Stream(...);           // PEM, after GenerateCSR
procedure SavePrivateKeyToFile/Stream(...);    // unencrypted PEM
procedure SavePublicKeyToFile/Stream(...);
property PrivateKey: TRSAPrivateKey;           // the generated key (owned by TReqUtil)
```

Each `Generate*` call creates a fresh RSA key pair. The self-signed certificate has issuer = subject.

```delphi
uses OpenSSL.Core, OpenSSL.ReqUtils;

var
  LReqUtil: TReqUtil;
begin
  LReqUtil := TReqUtil.Create;
  try
    LReqUtil.GenerateSelfSignedCertificate('/CN=localhost/O=MyCompany/C=IT', 365, 2048);
    LReqUtil.SaveCertificateToFile('cert.pem');
    LReqUtil.SavePrivateKeyToFile('key.pem');
  finally
    LReqUtil.Free;
  end;
end;

// CSR to send to a CA
LReqUtil.GenerateCSR(TSubjectInfo.Create('CN=api.example.com,O=Example,C=US', ','), 3072);
LReqUtil.SaveCSRToFile('api.csr');
LReqUtil.SavePrivateKeyToFile('api.key');
```

Not supported: signing a CSR with your own CA, extensions (SAN, key usage), EC keys. For these, use the OpenSSL command line or raw `OpenSSL.Api` calls.
