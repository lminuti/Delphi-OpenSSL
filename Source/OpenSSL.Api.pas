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
unit OpenSSL.Api;

// Low level OpenSSL C API plus the runtime loader. Prototypes and data structures
// are adapted from the TaurusTLS headers (https://github.com/JPeterMugaas/TaurusTLS,
// Apache-2.0) but simplified: only the functions actually used by this library are
// declared, as plain procedural variables filled in by TOpenSSLLoader at load time.

interface

uses
  System.Classes;

type
  PIdAnsiChar = PAnsiChar;

  BIO = record end;
  PBIO = ^BIO;
  BIO_METHOD = Pointer;
  PBIO_METHOD = ^BIO_METHOD;

  EVP_CIPHER = record end;
  PEVP_CIPHER = ^EVP_CIPHER;
  EVP_CIPHER_CTX = record end;
  PEVP_CIPHER_CTX = ^EVP_CIPHER_CTX;
  EVP_MD = record end;
  PEVP_MD = ^EVP_MD;
  EVP_MD_CTX = record end;
  PEVP_MD_CTX = ^EVP_MD_CTX;
  EVP_PKEY = record end;
  PEVP_PKEY = ^EVP_PKEY;
  PPEVP_PKEY = ^PEVP_PKEY;
  EVP_PKEY_CTX = record end;
  PEVP_PKEY_CTX = ^EVP_PKEY_CTX;
  PPEVP_PKEY_CTX = ^PEVP_PKEY_CTX;

  ENGINE = record end;
  PENGINE = ^ENGINE;

  BIGNUM = record end;
  PBIGNUM = ^BIGNUM;
  BN_GENCB = record end;
  PBN_GENCB = ^BN_GENCB;

  RSA = record end;
  PRSA = ^RSA;
  PPRSA = ^PRSA;

  ASN1_INTEGER = record end;
  PASN1_INTEGER = ^ASN1_INTEGER;
  ASN1_TIME = record end;
  PASN1_TIME = ^ASN1_TIME;
  X509_NAME = record end;
  PX509_NAME = ^X509_NAME;

  // Minimal X509 / X509_REQ layouts. Only the leading fields are declared;
  // they are used to emulate the X509_get_version / X509_get_notBefore /
  // X509_get_notAfter / X509_REQ_get_subject_name macros on OpenSSL 1.0.
  X509_VAL = record
    notBefore: PASN1_TIME;
    notAfter: PASN1_TIME;
  end;
  PX509_VAL = ^X509_VAL;

  X509_CINF = record
    version: PASN1_INTEGER;
    serialNumber: PASN1_INTEGER;
    signature: Pointer;
    issuer: PX509_NAME;
    validity: PX509_VAL;
    subject: PX509_NAME;
  end;
  PX509_CINF = ^X509_CINF;

  X509 = record
    cert_info: PX509_CINF;
  end;
  PX509 = ^X509;
  PPX509 = ^PX509;

  ASN1_ENCODING = record
    enc: PByte;
    len: LongInt;
    modified: Integer;
  end;

  X509_REQ_INFO = record
    enc: ASN1_ENCODING;
    version: PASN1_INTEGER;
    subject: PX509_NAME;
    pubkey: Pointer;
  end;
  PX509_REQ_INFO = ^X509_REQ_INFO;

  X509_REQ = record
    req_info: PX509_REQ_INFO;
  end;
  PX509_REQ = ^X509_REQ;

  X509_STORE = record end;
  PX509_STORE = ^X509_STORE;

  STACK_OF_X509 = record end;
  PSTACK_OF_X509 = ^STACK_OF_X509;

  PKCS7 = record end;
  PPKCS7 = ^PKCS7;
  PPPKCS7 = ^PPKCS7;

  pem_password_cb = function(buf: PAnsiChar; size: Integer; rwflag: Integer; userdata: Pointer): Integer; cdecl;
  TPEMPasswordCallback = pem_password_cb;

const
  OPENSSL_VERSION_NUMBER_1_1_0 = $10100000;
  OPENSSL_VERSION_NUMBER_3_0_0 = $30000000;

  PKCS5_SALT_LEN = 8;

  PKCS7_NOVERIFY = $20;

  RSA_PKCS1_PADDING = 1;
  RSA_SSLV23_PADDING = 2;
  RSA_NO_PADDING = 3;
  RSA_PKCS1_OAEP_PADDING = 4;
  RSA_F4 = $10001;

  NID_commonName = 13;
  NID_countryName = 14;
  NID_localityName = 15;
  NID_stateOrProvinceName = 16;
  NID_organizationName = 17;
  NID_organizationalUnitName = 18;
  NID_pkcs9_emailAddress = 48;

  MBSTRING_ASC = $1001;

  BIO_CTRL_INFO = 3;
  BIO_CTRL_PENDING = 10;
  BIO_CTRL_FLUSH = 11;
  BIO_C_GET_MD_CTX = 122;

var
  { version / errors }
  OpenSSL_version_num: function: Cardinal; cdecl;
  OpenSSL_version: function(type_: Integer): PAnsiChar; cdecl;
  OpenSSL_add_all_algorithms: procedure; cdecl;
  OpenSSL_add_all_digests: procedure; cdecl;
  OpenSSL_add_all_ciphers: procedure; cdecl;
  ERR_get_error: function: Cardinal; cdecl;
  ERR_error_string: function(e: Cardinal; buf: PAnsiChar): PAnsiChar; cdecl;
  ERR_load_crypto_strings: procedure; cdecl;

  { BIO }
  BIO_new: function(const cType: PBIO_METHOD): PBIO; cdecl;
  BIO_free: function(a: PBIO): Integer; cdecl;
  BIO_free_all: procedure(a: PBIO); cdecl;
  BIO_push: function(b: PBIO; a: PBIO): PBIO; cdecl;
  BIO_s_mem: function: PBIO_METHOD; cdecl;
  BIO_f_md: function: PBIO_METHOD; cdecl;
  BIO_f_base64: function: PBIO_METHOD; cdecl;
  BIO_read: function(b: PBIO; data: Pointer; dlen: Integer): Integer; cdecl;
  BIO_write: function(b: PBIO; const data: Pointer; dlen: Integer): Integer; cdecl;
  BIO_ctrl: function(bp: PBIO; cmd: Integer; larg: LongInt; parg: Pointer): LongInt; cdecl;
  BIO_new_mem_buf: function(const buf: Pointer; len: Integer): PBIO; cdecl;
  BIO_number_written: function(bio: PBIO): UInt64; cdecl;

  { EVP cipher context }
  EVP_CIPHER_CTX_new: function: PEVP_CIPHER_CTX; cdecl;
  EVP_CIPHER_CTX_free: procedure(c: PEVP_CIPHER_CTX); cdecl;
  EVP_CIPHER_iv_length: function(const cipher: PEVP_CIPHER): Integer; cdecl;
  EVP_CIPHER_key_length: function(const cipher: PEVP_CIPHER): Integer; cdecl;
  _EVP_CIPHER_CTX_block_size: function(const ctx: PEVP_CIPHER_CTX): Integer; cdecl;
  _EVP_CIPHER_get_block_size: function(const cipher: PEVP_CIPHER): Integer; cdecl;
  _EVP_CIPHER_CTX_get0_cipher: function(const ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl;
  EVP_EncryptInit_ex: function(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): Integer; cdecl;
  EVP_DecryptInit_ex: function(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): Integer; cdecl;
  EVP_EncryptUpdate: function(ctx: PEVP_CIPHER_CTX; out_: PByte; outl: PInteger; in_: PByte; inl: Integer): Integer; cdecl;
  EVP_EncryptFinal_ex: function(ctx: PEVP_CIPHER_CTX; out_: PByte; outl: PInteger): Integer; cdecl;
  EVP_DecryptUpdate: function(ctx: PEVP_CIPHER_CTX; out_: PByte; outl: PInteger; in_: PByte; inl: Integer): Integer; cdecl;
  EVP_DecryptFinal_ex: function(ctx: PEVP_CIPHER_CTX; outm: PByte; outl: PInteger): Integer; cdecl;
  EVP_BytesToKey: function(const type_: PEVP_CIPHER; const md: PEVP_MD; const salt: PByte; const data: PByte; datal: Integer; count: Integer; key: PByte; iv: PByte): Integer; cdecl;

  { EVP digests / keys }
  EVP_md5: function: PEVP_MD; cdecl;
  EVP_sha256: function: PEVP_MD; cdecl;
  EVP_MD_CTX_create: function: PEVP_MD_CTX; cdecl;
  EVP_MD_CTX_destroy: procedure(ctx: PEVP_MD_CTX); cdecl;
  EVP_DigestUpdate: function(ctx: PEVP_MD_CTX; const d: Pointer; cnt: NativeUInt): Integer; cdecl;
  EVP_DigestSignInit: function(ctx: PEVP_MD_CTX; pctx: Pointer; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): Integer; cdecl;
  EVP_DigestSignFinal: function(ctx: PEVP_MD_CTX; sigret: PByte; siglen: Pointer): Integer; cdecl;
  EVP_DigestVerifyInit: function(ctx: PEVP_MD_CTX; pctx: Pointer; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): Integer; cdecl;
  EVP_DigestVerifyFinal: function(ctx: PEVP_MD_CTX; const sig: PByte; siglen: NativeUInt): Integer; cdecl;
  EVP_PKEY_new: function: PEVP_PKEY; cdecl;
  EVP_PKEY_free: procedure(pkey: PEVP_PKEY); cdecl;
  EVP_PKEY_set1_RSA: function(pkey: PEVP_PKEY; key: PRSA): Integer; cdecl;
  EVP_PKEY_get1_RSA: function(pkey: PEVP_PKEY): PRSA; cdecl;

  { EVP cipher factories }
  EVP_aes_128_cbc: function: PEVP_CIPHER; cdecl;
  EVP_aes_192_cbc: function: PEVP_CIPHER; cdecl;
  EVP_aes_256_cbc: function: PEVP_CIPHER; cdecl;
  EVP_aes_128_cfb128: function: PEVP_CIPHER; cdecl;
  EVP_aes_192_cfb128: function: PEVP_CIPHER; cdecl;
  EVP_aes_256_cfb128: function: PEVP_CIPHER; cdecl;
  EVP_aes_128_cfb1: function: PEVP_CIPHER; cdecl;
  EVP_aes_192_cfb1: function: PEVP_CIPHER; cdecl;
  EVP_aes_256_cfb1: function: PEVP_CIPHER; cdecl;
  EVP_aes_128_cfb8: function: PEVP_CIPHER; cdecl;
  EVP_aes_192_cfb8: function: PEVP_CIPHER; cdecl;
  EVP_aes_256_cfb8: function: PEVP_CIPHER; cdecl;
  EVP_aes_128_ecb: function: PEVP_CIPHER; cdecl;
  EVP_aes_192_ecb: function: PEVP_CIPHER; cdecl;
  EVP_aes_256_ecb: function: PEVP_CIPHER; cdecl;
  EVP_aes_128_ofb: function: PEVP_CIPHER; cdecl;
  EVP_aes_192_ofb: function: PEVP_CIPHER; cdecl;
  EVP_aes_256_ofb: function: PEVP_CIPHER; cdecl;
  EVP_bf_cbc: function: PEVP_CIPHER; cdecl;
  EVP_bf_ecb: function: PEVP_CIPHER; cdecl;
  EVP_bf_cfb64: function: PEVP_CIPHER; cdecl;
  EVP_bf_ofb: function: PEVP_CIPHER; cdecl;
  EVP_des_cbc: function: PEVP_CIPHER; cdecl;
  EVP_des_cfb64: function: PEVP_CIPHER; cdecl;
  EVP_des_ofb: function: PEVP_CIPHER; cdecl;
  EVP_des_ecb: function: PEVP_CIPHER; cdecl;
  EVP_des_ede_cbc: function: PEVP_CIPHER; cdecl;
  EVP_des_ede: function: PEVP_CIPHER; cdecl;
  EVP_des_ede_cfb64: function: PEVP_CIPHER; cdecl;
  EVP_des_ede_ofb: function: PEVP_CIPHER; cdecl;
  EVP_des_ede3_cbc: function: PEVP_CIPHER; cdecl;
  EVP_des_ede3: function: PEVP_CIPHER; cdecl;
  EVP_des_ede3_cfb64: function: PEVP_CIPHER; cdecl;
  EVP_des_ede3_ofb: function: PEVP_CIPHER; cdecl;
  EVP_desx_cbc: function: PEVP_CIPHER; cdecl;
  EVP_idea_cbc: function: PEVP_CIPHER; cdecl;
  EVP_idea_cfb64: function: PEVP_CIPHER; cdecl;
  EVP_idea_ecb: function: PEVP_CIPHER; cdecl;
  EVP_idea_ofb: function: PEVP_CIPHER; cdecl;
  EVP_rc2_cbc: function: PEVP_CIPHER; cdecl;
  EVP_rc2_cfb64: function: PEVP_CIPHER; cdecl;
  EVP_rc2_ecb: function: PEVP_CIPHER; cdecl;
  EVP_rc2_ofb: function: PEVP_CIPHER; cdecl;
  EVP_rc4: function: PEVP_CIPHER; cdecl;
  EVP_rc4_40: function: PEVP_CIPHER; cdecl;

  { BIGNUM }
  BN_new: function: PBIGNUM; cdecl;
  BN_free: procedure(a: PBIGNUM); cdecl;
  BN_set_word: function(a: PBIGNUM; w: NativeUInt): Integer; cdecl;
  BN_num_bits: function(a: PBIGNUM): Integer; cdecl;
  BN_bn2bin: function(const a: PBIGNUM; to_: PByte): Integer; cdecl;

  { RSA }
  RSA_new: function: PRSA; cdecl;
  RSA_free: procedure(r: PRSA); cdecl;
  RSA_size: function(const rsa: PRSA): Integer; cdecl;
  RSA_public_encrypt: function(flen: Integer; const from_: PByte; to_: PByte; rsa: PRSA; padding: Integer): Integer; cdecl;
  RSA_private_decrypt: function(flen: Integer; const from_: PByte; to_: PByte; rsa: PRSA; padding: Integer): Integer; cdecl;
  RSA_generate_key_ex: function(rsa: PRSA; bits: Integer; e: PBIGNUM; cb: PBN_GENCB): Integer; cdecl;
  RSA_print: function(bp: PBIO; const r: PRSA; offset: Integer): Integer; cdecl;

  { X509 }
  X509_new: function: PX509; cdecl;
  X509_free: procedure(v1: PX509); cdecl;
  X509_get_pubkey: function(x: PX509): PEVP_PKEY; cdecl;
  X509_set_version: function(x: PX509; version: LongInt): Integer; cdecl;
  X509_get_version: function(const x: PX509): LongInt; cdecl;
  X509_get_serialNumber: function(x: PX509): PASN1_INTEGER; cdecl;
  X509_get_subject_name: function(const a: PX509): PX509_NAME; cdecl;
  X509_get_issuer_name: function(const a: PX509): PX509_NAME; cdecl;
  X509_set_issuer_name: function(x: PX509; name: PX509_NAME): Integer; cdecl;
  X509_set_pubkey: function(x: PX509; pkey: PEVP_PKEY): Integer; cdecl;
  X509_sign: function(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): Integer; cdecl;
  X509_gmtime_adj: function(s: PASN1_TIME; adj: LongInt): PASN1_TIME; cdecl;
  X509_get_notBefore: function(const x: PX509): PASN1_TIME; cdecl;
  X509_get_notAfter: function(const x: PX509): PASN1_TIME; cdecl;
  X509_NAME_get_text_by_NID: function(name: PX509_NAME; nid: Integer; buf: PAnsiChar; len: Integer): Integer; cdecl;
  X509_NAME_add_entry_by_txt: function(name: PX509_NAME; const field: PAnsiChar; type_: Integer; const bytes: PByte; len: Integer; loc: Integer; set_: Integer): Integer; cdecl;
  X509_REQ_new: function: PX509_REQ; cdecl;
  X509_REQ_free: procedure(v1: PX509_REQ); cdecl;
  X509_REQ_set_version: function(x: PX509_REQ; version: LongInt): Integer; cdecl;
  X509_REQ_get_subject_name: function(const req: PX509_REQ): PX509_NAME; cdecl;
  X509_REQ_set_pubkey: function(x: PX509_REQ; pkey: PEVP_PKEY): Integer; cdecl;
  X509_REQ_sign: function(x: PX509_REQ; pkey: PEVP_PKEY; const md: PEVP_MD): Integer; cdecl;

  { ASN1 }
  ASN1_INTEGER_set: function(a: PASN1_INTEGER; v: LongInt): Integer; cdecl;
  ASN1_INTEGER_get: function(a: PASN1_INTEGER): LongInt; cdecl;
  ASN1_INTEGER_to_BN: function(const ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM; cdecl;
  ASN1_TIME_print: function(fp: PBIO; const a: PASN1_TIME): Integer; cdecl;

  { PEM }
  PEM_read_bio_X509: function(bp: PBIO; x: PPX509; cb: TPEMPasswordCallback; u: Pointer): PX509; cdecl;
  PEM_read_bio_PrivateKey: function(bp: PBIO; x: PPEVP_PKEY; cb: TPEMPasswordCallback; u: Pointer): PEVP_PKEY; cdecl;
  PEM_read_bio_RSAPrivateKey: function(bp: PBIO; x: PPRSA; cb: TPEMPasswordCallback; u: Pointer): PRSA; cdecl;
  PEM_read_bio_PUBKEY: function(bp: PBIO; x: PPEVP_PKEY; cb: TPEMPasswordCallback; u: Pointer): PEVP_PKEY; cdecl;
  PEM_read_bio_RSAPublicKey: function(bp: PBIO; x: PPRSA; cb: TPEMPasswordCallback; u: Pointer): PRSA; cdecl;
  PEM_write_bio_PrivateKey: function(bp: PBIO; x: PEVP_PKEY; const enc: PEVP_CIPHER; kstr: PByte; klen: Integer; cb: TPEMPasswordCallback; u: Pointer): Integer; cdecl;
  PEM_write_bio_RSAPrivateKey: function(bp: PBIO; x: PRSA; const enc: PEVP_CIPHER; kstr: PByte; klen: Integer; cb: TPEMPasswordCallback; u: Pointer): Integer; cdecl;
  PEM_write_bio_PUBKEY: function(bp: PBIO; x: PEVP_PKEY): Integer; cdecl;
  PEM_write_bio_RSAPublicKey: function(bp: PBIO; const x: PRSA): Integer; cdecl;
  PEM_write_bio_X509: function(bp: PBIO; x: PX509): Integer; cdecl;
  PEM_write_bio_X509_REQ: function(bp: PBIO; x: PX509_REQ): Integer; cdecl;

  { PKCS7 }
  X509_STORE_new: function: PX509_STORE; cdecl;
  d2i_PKCS7_bio: function(bp: PBIO; p7: PPPKCS7): PPKCS7; cdecl;
  PKCS7_verify: function(p7: PPKCS7; certs: PSTACK_OF_X509; store: PX509_STORE; indata: PBIO; out_: PBIO; flags: Integer): Integer; cdecl;

  { RAND }
  RAND_bytes: function(buf: PByte; num: Integer): Integer; cdecl;
  RAND_status: function: Integer; cdecl;
  RAND_poll: function: Integer; cdecl;
  RAND_file_name: function(buf: PAnsiChar; num: Integer): PAnsiChar; cdecl;
  RAND_load_file: function(const file_: PAnsiChar; max_bytes: LongInt): Integer; cdecl;
  RAND_write_file: function(const file_: PAnsiChar): Integer; cdecl;

// EVP_DigestSignUpdate/VerifyUpdate are macros for EVP_DigestUpdate in OpenSSL
function EVP_DigestSignUpdate(ctx: PEVP_MD_CTX; const d: Pointer; cnt: NativeUInt): Integer;
function EVP_DigestVerifyUpdate(ctx: PEVP_MD_CTX; const d: Pointer; cnt: NativeUInt): Integer;

// BN_num_bytes is a macro in OpenSSL
function BN_num_bytes(a: PBIGNUM): Integer;

// EVP_CIPHER_CTX_block_size was removed in OpenSSL 3.0 in favour of
// EVP_CIPHER_get_block_size(EVP_CIPHER_CTX_get0_cipher(ctx))
function EVP_CIPHER_CTX_block_size(const ctx: PEVP_CIPHER_CTX): Integer;

type
  TOpenSSLLoader = class
  private
    FLibHandle: NativeUInt;
    FSSLLibVersions: string;
    FOpenSSLPath: string;
    FFailedToLoad: TStringList;
    FLoaded: Boolean;
    FVersionNum: Cardinal;
    function FindLibrary: NativeUInt;
    function GetProc(const AName: string): Pointer;
    function LoadFunc(const AName: string; ARequired: Boolean = True): Pointer;
    procedure LoadFunctions;
    procedure ClearFunctions;
  public
    constructor Create;
    destructor Destroy; override;

    // Loads the libcrypto library. Returns True if the library is loaded.
    function Load: Boolean;
    // Unloads the library and resets all the function pointers.
    procedure Unload;
    function IsLoaded: Boolean;

    // ';' separated list of library file names (without extension on Windows)
    // tried in order, eg. 'libcrypto-4;libcrypto-3;libcrypto-1_1;libeay32'
    property SSLLibVersions: string read FSSLLibVersions write FSSLLibVersions;
    // Directory where the library is searched. Empty means the system search path.
    property OpenSSLPath: string read FOpenSSLPath write FOpenSSLPath;
    // Functions that could not be resolved. Informational only.
    property FailedToLoad: TStringList read FFailedToLoad;
    // Numerical OpenSSL version (OpenSSL_version_num), 0 if unknown.
    property VersionNum: Cardinal read FVersionNum;
  end;

function GetOpenSSLLoader: TOpenSSLLoader;

implementation

uses
  System.SysUtils,
  {$IFDEF MSWINDOWS}
  Winapi.Windows;
  {$ENDIF}
  {$IFDEF POSIX}
  Posix.Dlfcn;
  {$ENDIF}

type
  TOpenSSLVersionNumFn = function: Cardinal; cdecl;

{ macros / helpers }

function EVP_DigestSignUpdate(ctx: PEVP_MD_CTX; const d: Pointer; cnt: NativeUInt): Integer;
begin
  Result := EVP_DigestUpdate(ctx, d, cnt);
end;

function EVP_DigestVerifyUpdate(ctx: PEVP_MD_CTX; const d: Pointer; cnt: NativeUInt): Integer;
begin
  Result := EVP_DigestUpdate(ctx, d, cnt);
end;

function BN_num_bytes(a: PBIGNUM): Integer;
begin
  Result := (BN_num_bits(a) + 7) div 8;
end;

function EVP_CIPHER_CTX_block_size(const ctx: PEVP_CIPHER_CTX): Integer;
begin
  if Assigned(_EVP_CIPHER_CTX_block_size) then
    Result := _EVP_CIPHER_CTX_block_size(ctx)
  else if Assigned(_EVP_CIPHER_get_block_size) and Assigned(_EVP_CIPHER_CTX_get0_cipher) then
    Result := _EVP_CIPHER_get_block_size(_EVP_CIPHER_CTX_get0_cipher(ctx))
  else
    Result := 0;
end;

{ OpenSSL 1.0 fallbacks for accessors that are macros there instead of exported
  functions. They are installed by the loader only for versions before 1.1. }

function X509_get_version_fallback(const x: PX509): LongInt; cdecl;
begin
  if (x = nil) or (x^.cert_info = nil) then
    Exit(0);
  Result := ASN1_INTEGER_get(x^.cert_info^.version);
end;

function X509_get_notBefore_fallback(const x: PX509): PASN1_TIME; cdecl;
begin
  if (x = nil) or (x^.cert_info = nil) or (x^.cert_info^.validity = nil) then
    Exit(nil);
  Result := x^.cert_info^.validity^.notBefore;
end;

function X509_get_notAfter_fallback(const x: PX509): PASN1_TIME; cdecl;
begin
  if (x = nil) or (x^.cert_info = nil) or (x^.cert_info^.validity = nil) then
    Exit(nil);
  Result := x^.cert_info^.validity^.notAfter;
end;

function X509_REQ_get_subject_name_fallback(const req: PX509_REQ): PX509_NAME; cdecl;
begin
  if (req = nil) or (req^.req_info = nil) then
    Exit(nil);
  Result := req^.req_info^.subject;
end;

{ loader internals }

// Assigns a raw pointer to a (function) pointer variable of any type.
procedure AssignProc(var ADest; Src: Pointer);
begin
  PPointer(@ADest)^ := Src;
end;

function DefaultSSLLibVersions: string;
begin
  {$IFDEF MSWINDOWS}
    {$IFDEF CPUARM64}
    Result := 'libcrypto-4-arm64;libcrypto-3-arm64;libcrypto-1_1-arm64;libeay32';
    {$ELSE}
      {$IFDEF WIN64}
      Result := 'libcrypto-4-x64;libcrypto-3-x64;libcrypto-1_1-x64;libeay32';
      {$ELSE}
      Result := 'libcrypto-4;libcrypto-3;libcrypto-1_1;libeay32';
      {$ENDIF}
    {$ENDIF}
  {$ELSE}
  Result := 'libcrypto.so.4;libcrypto.so.3;libcrypto.so.1.1;libcrypto.so.1.0.0';
  {$ENDIF}
end;

function BuildLibFileName(const AToken: string): string;
begin
  {$IFDEF MSWINDOWS}
  if SameText(ExtractFileExt(AToken), '.dll') then
    Result := AToken
  else
    Result := AToken + '.dll';
  {$ELSE}
  if Pos('.so', AToken) > 0 then
    Result := AToken
  else
    Result := AToken + '.so';
  {$ENDIF}
end;

function DoLoadLibrary(const AFileName: string): NativeUInt;
begin
  {$IFDEF MSWINDOWS}
  Result := NativeUInt(SafeLoadLibrary(AFileName));
  {$ENDIF}
  {$IFDEF POSIX}
  Result := NativeUInt(dlopen(PAnsiChar(AnsiString(AFileName)), RTLD_NOW));
  {$ENDIF}
end;

function DoGetProcAddress(ALibHandle: NativeUInt; const AName: string): Pointer;
begin
  {$IFDEF MSWINDOWS}
  Result := GetProcAddress(HMODULE(ALibHandle), PAnsiChar(AnsiString(AName)));
  {$ENDIF}
  {$IFDEF POSIX}
  Result := dlsym(Pointer(ALibHandle), PAnsiChar(AnsiString(AName)));
  {$ENDIF}
end;

procedure DoFreeLibrary(ALibHandle: NativeUInt);
begin
  {$IFDEF MSWINDOWS}
  FreeLibrary(HMODULE(ALibHandle));
  {$ENDIF}
  {$IFDEF POSIX}
  dlclose(Pointer(ALibHandle));
  {$ENDIF}
end;

var
  GOpenSSLLoader: TOpenSSLLoader = nil;

function GetOpenSSLLoader: TOpenSSLLoader;
begin
  if GOpenSSLLoader = nil then
    GOpenSSLLoader := TOpenSSLLoader.Create;
  Result := GOpenSSLLoader;
end;

{ TOpenSSLLoader }

constructor TOpenSSLLoader.Create;
begin
  inherited;
  FFailedToLoad := TStringList.Create;
  FSSLLibVersions := DefaultSSLLibVersions;
  OpenSSLPath := GetEnvironmentVariable('OPENSSL_LIBRARY_PATH');
end;

destructor TOpenSSLLoader.Destroy;
begin
  Unload;
  FFailedToLoad.Free;
  inherited;
end;

function TOpenSSLLoader.FindLibrary: NativeUInt;
var
  Tokens: TStringList;
  i: Integer;
begin
  Result := 0;
  Tokens := TStringList.Create;
  try
    Tokens.Delimiter := ';';
    Tokens.StrictDelimiter := True;
    Tokens.DelimitedText := FSSLLibVersions;
    for i := 0 to Tokens.Count - 1 do
    begin
      if Tokens[i] = '' then
        Continue;
      Result := DoLoadLibrary(FOpenSSLPath + BuildLibFileName(Tokens[i]));
      if Result <> 0 then
        Exit;
    end;
  finally
    Tokens.Free;
  end;
end;

function TOpenSSLLoader.GetProc(const AName: string): Pointer;
begin
  Result := DoGetProcAddress(FLibHandle, AName);
end;

function TOpenSSLLoader.LoadFunc(const AName: string; ARequired: Boolean): Pointer;
begin
  Result := GetProc(AName);
  if (Result = nil) and ARequired then
    FFailedToLoad.Add(AName);
end;

procedure TOpenSSLLoader.LoadFunctions;
var
  Is11OrAbove: Boolean;
  Is30OrAbove: Boolean;
begin
  Is11OrAbove := FVersionNum >= OPENSSL_VERSION_NUMBER_1_1_0;
  Is30OrAbove := FVersionNum >= OPENSSL_VERSION_NUMBER_3_0_0;

  { version string }
  if Is11OrAbove then
    AssignProc(OpenSSL_version, LoadFunc('OpenSSL_version'))
  else
    AssignProc(OpenSSL_version, LoadFunc('SSLeay_version'));

  { initialization and errors (only needed by 1.0, no-op or absent later) }
  AssignProc(OpenSSL_add_all_algorithms, LoadFunc('OpenSSL_add_all_algorithms', False));
  AssignProc(OpenSSL_add_all_digests, LoadFunc('OpenSSL_add_all_digests', False));
  AssignProc(OpenSSL_add_all_ciphers, LoadFunc('OpenSSL_add_all_ciphers', False));
  AssignProc(ERR_load_crypto_strings, LoadFunc('ERR_load_crypto_strings', False));
  AssignProc(ERR_get_error, LoadFunc('ERR_get_error'));
  AssignProc(ERR_error_string, LoadFunc('ERR_error_string'));

  { BIO }
  AssignProc(BIO_new, LoadFunc('BIO_new'));
  AssignProc(BIO_free, LoadFunc('BIO_free'));
  AssignProc(BIO_free_all, LoadFunc('BIO_free_all'));
  AssignProc(BIO_push, LoadFunc('BIO_push'));
  AssignProc(BIO_s_mem, LoadFunc('BIO_s_mem'));
  AssignProc(BIO_f_md, LoadFunc('BIO_f_md'));
  AssignProc(BIO_f_base64, LoadFunc('BIO_f_base64'));
  AssignProc(BIO_read, LoadFunc('BIO_read'));
  AssignProc(BIO_write, LoadFunc('BIO_write'));
  AssignProc(BIO_ctrl, LoadFunc('BIO_ctrl'));
  AssignProc(BIO_new_mem_buf, LoadFunc('BIO_new_mem_buf'));
  AssignProc(BIO_number_written, LoadFunc('BIO_number_written'));

  { EVP cipher context }
  AssignProc(EVP_CIPHER_CTX_new, LoadFunc('EVP_CIPHER_CTX_new'));
  AssignProc(EVP_CIPHER_CTX_free, LoadFunc('EVP_CIPHER_CTX_free'));
  AssignProc(EVP_EncryptInit_ex, LoadFunc('EVP_EncryptInit_ex'));
  AssignProc(EVP_DecryptInit_ex, LoadFunc('EVP_DecryptInit_ex'));
  AssignProc(EVP_EncryptUpdate, LoadFunc('EVP_EncryptUpdate'));
  AssignProc(EVP_EncryptFinal_ex, LoadFunc('EVP_EncryptFinal_ex'));
  AssignProc(EVP_DecryptUpdate, LoadFunc('EVP_DecryptUpdate'));
  AssignProc(EVP_DecryptFinal_ex, LoadFunc('EVP_DecryptFinal_ex'));
  AssignProc(EVP_BytesToKey, LoadFunc('EVP_BytesToKey'));

  if Is30OrAbove then
  begin
    AssignProc(EVP_CIPHER_iv_length, LoadFunc('EVP_CIPHER_get_iv_length'));
    AssignProc(EVP_CIPHER_key_length, LoadFunc('EVP_CIPHER_get_key_length'));
    AssignProc(_EVP_CIPHER_get_block_size, LoadFunc('EVP_CIPHER_get_block_size'));
    AssignProc(_EVP_CIPHER_CTX_get0_cipher, LoadFunc('EVP_CIPHER_CTX_get0_cipher'));
  end
  else
  begin
    AssignProc(EVP_CIPHER_iv_length, LoadFunc('EVP_CIPHER_iv_length'));
    AssignProc(EVP_CIPHER_key_length, LoadFunc('EVP_CIPHER_key_length'));
    AssignProc(_EVP_CIPHER_CTX_block_size, LoadFunc('EVP_CIPHER_CTX_block_size'));
  end;

  { EVP digests / keys }
  AssignProc(EVP_md5, LoadFunc('EVP_md5'));
  AssignProc(EVP_sha256, LoadFunc('EVP_sha256'));
  AssignProc(EVP_DigestUpdate, LoadFunc('EVP_DigestUpdate'));
  AssignProc(EVP_DigestSignInit, LoadFunc('EVP_DigestSignInit'));
  AssignProc(EVP_DigestSignFinal, LoadFunc('EVP_DigestSignFinal'));
  AssignProc(EVP_DigestVerifyInit, LoadFunc('EVP_DigestVerifyInit'));
  AssignProc(EVP_DigestVerifyFinal, LoadFunc('EVP_DigestVerifyFinal'));
  if Is11OrAbove then
  begin
    AssignProc(EVP_MD_CTX_create, LoadFunc('EVP_MD_CTX_new'));
    AssignProc(EVP_MD_CTX_destroy, LoadFunc('EVP_MD_CTX_free'));
  end
  else
  begin
    AssignProc(EVP_MD_CTX_create, LoadFunc('EVP_MD_CTX_create'));
    AssignProc(EVP_MD_CTX_destroy, LoadFunc('EVP_MD_CTX_destroy'));
  end;
  AssignProc(EVP_PKEY_new, LoadFunc('EVP_PKEY_new'));
  AssignProc(EVP_PKEY_free, LoadFunc('EVP_PKEY_free'));
  AssignProc(EVP_PKEY_set1_RSA, LoadFunc('EVP_PKEY_set1_RSA'));
  AssignProc(EVP_PKEY_get1_RSA, LoadFunc('EVP_PKEY_get1_RSA'));

  { cipher factories (optional, some legacy ciphers are not exported by 3.x/4.x) }
  AssignProc(EVP_aes_128_cbc, LoadFunc('EVP_aes_128_cbc', False));
  AssignProc(EVP_aes_192_cbc, LoadFunc('EVP_aes_192_cbc', False));
  AssignProc(EVP_aes_256_cbc, LoadFunc('EVP_aes_256_cbc', False));
  AssignProc(EVP_aes_128_cfb128, LoadFunc('EVP_aes_128_cfb128', False));
  AssignProc(EVP_aes_192_cfb128, LoadFunc('EVP_aes_192_cfb128', False));
  AssignProc(EVP_aes_256_cfb128, LoadFunc('EVP_aes_256_cfb128', False));
  AssignProc(EVP_aes_128_cfb1, LoadFunc('EVP_aes_128_cfb1', False));
  AssignProc(EVP_aes_192_cfb1, LoadFunc('EVP_aes_192_cfb1', False));
  AssignProc(EVP_aes_256_cfb1, LoadFunc('EVP_aes_256_cfb1', False));
  AssignProc(EVP_aes_128_cfb8, LoadFunc('EVP_aes_128_cfb8', False));
  AssignProc(EVP_aes_192_cfb8, LoadFunc('EVP_aes_192_cfb8', False));
  AssignProc(EVP_aes_256_cfb8, LoadFunc('EVP_aes_256_cfb8', False));
  AssignProc(EVP_aes_128_ecb, LoadFunc('EVP_aes_128_ecb', False));
  AssignProc(EVP_aes_192_ecb, LoadFunc('EVP_aes_192_ecb', False));
  AssignProc(EVP_aes_256_ecb, LoadFunc('EVP_aes_256_ecb', False));
  AssignProc(EVP_aes_128_ofb, LoadFunc('EVP_aes_128_ofb', False));
  AssignProc(EVP_aes_192_ofb, LoadFunc('EVP_aes_192_ofb', False));
  AssignProc(EVP_aes_256_ofb, LoadFunc('EVP_aes_256_ofb', False));
  AssignProc(EVP_bf_cbc, LoadFunc('EVP_bf_cbc', False));
  AssignProc(EVP_bf_ecb, LoadFunc('EVP_bf_ecb', False));
  AssignProc(EVP_bf_cfb64, LoadFunc('EVP_bf_cfb64', False));
  AssignProc(EVP_bf_ofb, LoadFunc('EVP_bf_ofb', False));
  AssignProc(EVP_des_cbc, LoadFunc('EVP_des_cbc', False));
  AssignProc(EVP_des_cfb64, LoadFunc('EVP_des_cfb64', False));
  AssignProc(EVP_des_ofb, LoadFunc('EVP_des_ofb', False));
  AssignProc(EVP_des_ecb, LoadFunc('EVP_des_ecb', False));
  AssignProc(EVP_des_ede_cbc, LoadFunc('EVP_des_ede_cbc', False));
  AssignProc(EVP_des_ede, LoadFunc('EVP_des_ede', False));
  AssignProc(EVP_des_ede_cfb64, LoadFunc('EVP_des_ede_cfb64', False));
  AssignProc(EVP_des_ede_ofb, LoadFunc('EVP_des_ede_ofb', False));
  AssignProc(EVP_des_ede3_cbc, LoadFunc('EVP_des_ede3_cbc', False));
  AssignProc(EVP_des_ede3, LoadFunc('EVP_des_ede3', False));
  AssignProc(EVP_des_ede3_cfb64, LoadFunc('EVP_des_ede3_cfb64', False));
  AssignProc(EVP_des_ede3_ofb, LoadFunc('EVP_des_ede3_ofb', False));
  AssignProc(EVP_desx_cbc, LoadFunc('EVP_desx_cbc', False));
  AssignProc(EVP_idea_cbc, LoadFunc('EVP_idea_cbc', False));
  AssignProc(EVP_idea_cfb64, LoadFunc('EVP_idea_cfb64', False));
  AssignProc(EVP_idea_ecb, LoadFunc('EVP_idea_ecb', False));
  AssignProc(EVP_idea_ofb, LoadFunc('EVP_idea_ofb', False));
  AssignProc(EVP_rc2_cbc, LoadFunc('EVP_rc2_cbc', False));
  AssignProc(EVP_rc2_cfb64, LoadFunc('EVP_rc2_cfb64', False));
  AssignProc(EVP_rc2_ecb, LoadFunc('EVP_rc2_ecb', False));
  AssignProc(EVP_rc2_ofb, LoadFunc('EVP_rc2_ofb', False));
  AssignProc(EVP_rc4, LoadFunc('EVP_rc4', False));
  AssignProc(EVP_rc4_40, LoadFunc('EVP_rc4_40', False));

  { BIGNUM }
  AssignProc(BN_new, LoadFunc('BN_new'));
  AssignProc(BN_free, LoadFunc('BN_free'));
  AssignProc(BN_set_word, LoadFunc('BN_set_word'));
  AssignProc(BN_num_bits, LoadFunc('BN_num_bits'));
  AssignProc(BN_bn2bin, LoadFunc('BN_bn2bin'));

  { RSA }
  AssignProc(RSA_new, LoadFunc('RSA_new'));
  AssignProc(RSA_free, LoadFunc('RSA_free'));
  AssignProc(RSA_size, LoadFunc('RSA_size'));
  AssignProc(RSA_public_encrypt, LoadFunc('RSA_public_encrypt'));
  AssignProc(RSA_private_decrypt, LoadFunc('RSA_private_decrypt'));
  AssignProc(RSA_generate_key_ex, LoadFunc('RSA_generate_key_ex'));
  AssignProc(RSA_print, LoadFunc('RSA_print'));

  { X509 }
  AssignProc(X509_new, LoadFunc('X509_new'));
  AssignProc(X509_free, LoadFunc('X509_free'));
  AssignProc(X509_get_pubkey, LoadFunc('X509_get_pubkey'));
  AssignProc(X509_set_version, LoadFunc('X509_set_version'));
  if Is11OrAbove then
    AssignProc(X509_get_version, LoadFunc('X509_get_version'))
  else
    AssignProc(X509_get_version, @X509_get_version_fallback);
  AssignProc(X509_get_serialNumber, LoadFunc('X509_get_serialNumber'));
  AssignProc(X509_get_subject_name, LoadFunc('X509_get_subject_name'));
  AssignProc(X509_get_issuer_name, LoadFunc('X509_get_issuer_name'));
  AssignProc(X509_set_issuer_name, LoadFunc('X509_set_issuer_name'));
  AssignProc(X509_set_pubkey, LoadFunc('X509_set_pubkey'));
  AssignProc(X509_sign, LoadFunc('X509_sign'));
  AssignProc(X509_gmtime_adj, LoadFunc('X509_gmtime_adj'));
  if Is11OrAbove then
  begin
    AssignProc(X509_get_notBefore, LoadFunc('X509_get0_notBefore'));
    AssignProc(X509_get_notAfter, LoadFunc('X509_get0_notAfter'));
  end
  else
  begin
    AssignProc(X509_get_notBefore, @X509_get_notBefore_fallback);
    AssignProc(X509_get_notAfter, @X509_get_notAfter_fallback);
  end;
  AssignProc(X509_NAME_get_text_by_NID, LoadFunc('X509_NAME_get_text_by_NID'));
  AssignProc(X509_NAME_add_entry_by_txt, LoadFunc('X509_NAME_add_entry_by_txt'));
  AssignProc(X509_REQ_new, LoadFunc('X509_REQ_new'));
  AssignProc(X509_REQ_free, LoadFunc('X509_REQ_free'));
  AssignProc(X509_REQ_set_version, LoadFunc('X509_REQ_set_version'));
  if Is11OrAbove then
    AssignProc(X509_REQ_get_subject_name, LoadFunc('X509_REQ_get_subject_name'))
  else
    AssignProc(X509_REQ_get_subject_name, @X509_REQ_get_subject_name_fallback);
  AssignProc(X509_REQ_set_pubkey, LoadFunc('X509_REQ_set_pubkey'));
  AssignProc(X509_REQ_sign, LoadFunc('X509_REQ_sign'));

  { ASN1 }
  AssignProc(ASN1_INTEGER_set, LoadFunc('ASN1_INTEGER_set'));
  AssignProc(ASN1_INTEGER_get, LoadFunc('ASN1_INTEGER_get'));
  AssignProc(ASN1_INTEGER_to_BN, LoadFunc('ASN1_INTEGER_to_BN'));
  AssignProc(ASN1_TIME_print, LoadFunc('ASN1_TIME_print'));

  { PEM }
  AssignProc(PEM_read_bio_X509, LoadFunc('PEM_read_bio_X509'));
  AssignProc(PEM_read_bio_PrivateKey, LoadFunc('PEM_read_bio_PrivateKey'));
  AssignProc(PEM_read_bio_RSAPrivateKey, LoadFunc('PEM_read_bio_RSAPrivateKey'));
  AssignProc(PEM_read_bio_PUBKEY, LoadFunc('PEM_read_bio_PUBKEY'));
  AssignProc(PEM_read_bio_RSAPublicKey, LoadFunc('PEM_read_bio_RSAPublicKey'));
  AssignProc(PEM_write_bio_PrivateKey, LoadFunc('PEM_write_bio_PrivateKey'));
  AssignProc(PEM_write_bio_RSAPrivateKey, LoadFunc('PEM_write_bio_RSAPrivateKey'));
  AssignProc(PEM_write_bio_PUBKEY, LoadFunc('PEM_write_bio_PUBKEY'));
  AssignProc(PEM_write_bio_RSAPublicKey, LoadFunc('PEM_write_bio_RSAPublicKey'));
  AssignProc(PEM_write_bio_X509, LoadFunc('PEM_write_bio_X509'));
  AssignProc(PEM_write_bio_X509_REQ, LoadFunc('PEM_write_bio_X509_REQ'));

  { PKCS7 }
  AssignProc(X509_STORE_new, LoadFunc('X509_STORE_new'));
  AssignProc(d2i_PKCS7_bio, LoadFunc('d2i_PKCS7_bio'));
  AssignProc(PKCS7_verify, LoadFunc('PKCS7_verify'));

  { RAND }
  AssignProc(RAND_bytes, LoadFunc('RAND_bytes'));
  AssignProc(RAND_status, LoadFunc('RAND_status'));
  AssignProc(RAND_poll, LoadFunc('RAND_poll'));
  AssignProc(RAND_file_name, LoadFunc('RAND_file_name', False));
  AssignProc(RAND_load_file, LoadFunc('RAND_load_file'));
  AssignProc(RAND_write_file, LoadFunc('RAND_write_file'));
end;

procedure TOpenSSLLoader.ClearFunctions;
begin
  AssignProc(OpenSSL_version_num, nil);
  AssignProc(OpenSSL_version, nil);
  AssignProc(OpenSSL_add_all_algorithms, nil);
  AssignProc(OpenSSL_add_all_digests, nil);
  AssignProc(OpenSSL_add_all_ciphers, nil);
  AssignProc(ERR_get_error, nil);
  AssignProc(ERR_error_string, nil);
  AssignProc(ERR_load_crypto_strings, nil);
  AssignProc(BIO_new, nil);
  AssignProc(BIO_free, nil);
  AssignProc(BIO_free_all, nil);
  AssignProc(BIO_push, nil);
  AssignProc(BIO_s_mem, nil);
  AssignProc(BIO_f_md, nil);
  AssignProc(BIO_f_base64, nil);
  AssignProc(BIO_read, nil);
  AssignProc(BIO_write, nil);
  AssignProc(BIO_ctrl, nil);
  AssignProc(BIO_new_mem_buf, nil);
  AssignProc(BIO_number_written, nil);
  AssignProc(EVP_CIPHER_CTX_new, nil);
  AssignProc(EVP_CIPHER_CTX_free, nil);
  AssignProc(EVP_CIPHER_iv_length, nil);
  AssignProc(EVP_CIPHER_key_length, nil);
  AssignProc(_EVP_CIPHER_CTX_block_size, nil);
  AssignProc(_EVP_CIPHER_get_block_size, nil);
  AssignProc(_EVP_CIPHER_CTX_get0_cipher, nil);
  AssignProc(EVP_EncryptInit_ex, nil);
  AssignProc(EVP_DecryptInit_ex, nil);
  AssignProc(EVP_EncryptUpdate, nil);
  AssignProc(EVP_EncryptFinal_ex, nil);
  AssignProc(EVP_DecryptUpdate, nil);
  AssignProc(EVP_DecryptFinal_ex, nil);
  AssignProc(EVP_BytesToKey, nil);
  AssignProc(EVP_md5, nil);
  AssignProc(EVP_sha256, nil);
  AssignProc(EVP_MD_CTX_create, nil);
  AssignProc(EVP_MD_CTX_destroy, nil);
  AssignProc(EVP_DigestUpdate, nil);
  AssignProc(EVP_DigestSignInit, nil);
  AssignProc(EVP_DigestSignFinal, nil);
  AssignProc(EVP_DigestVerifyInit, nil);
  AssignProc(EVP_DigestVerifyFinal, nil);
  AssignProc(EVP_PKEY_new, nil);
  AssignProc(EVP_PKEY_free, nil);
  AssignProc(EVP_PKEY_set1_RSA, nil);
  AssignProc(EVP_PKEY_get1_RSA, nil);
  AssignProc(EVP_aes_128_cbc, nil);
  AssignProc(EVP_aes_192_cbc, nil);
  AssignProc(EVP_aes_256_cbc, nil);
  AssignProc(EVP_aes_128_cfb128, nil);
  AssignProc(EVP_aes_192_cfb128, nil);
  AssignProc(EVP_aes_256_cfb128, nil);
  AssignProc(EVP_aes_128_cfb1, nil);
  AssignProc(EVP_aes_192_cfb1, nil);
  AssignProc(EVP_aes_256_cfb1, nil);
  AssignProc(EVP_aes_128_cfb8, nil);
  AssignProc(EVP_aes_192_cfb8, nil);
  AssignProc(EVP_aes_256_cfb8, nil);
  AssignProc(EVP_aes_128_ecb, nil);
  AssignProc(EVP_aes_192_ecb, nil);
  AssignProc(EVP_aes_256_ecb, nil);
  AssignProc(EVP_aes_128_ofb, nil);
  AssignProc(EVP_aes_192_ofb, nil);
  AssignProc(EVP_aes_256_ofb, nil);
  AssignProc(EVP_bf_cbc, nil);
  AssignProc(EVP_bf_ecb, nil);
  AssignProc(EVP_bf_cfb64, nil);
  AssignProc(EVP_bf_ofb, nil);
  AssignProc(EVP_des_cbc, nil);
  AssignProc(EVP_des_cfb64, nil);
  AssignProc(EVP_des_ofb, nil);
  AssignProc(EVP_des_ecb, nil);
  AssignProc(EVP_des_ede_cbc, nil);
  AssignProc(EVP_des_ede, nil);
  AssignProc(EVP_des_ede_cfb64, nil);
  AssignProc(EVP_des_ede_ofb, nil);
  AssignProc(EVP_des_ede3_cbc, nil);
  AssignProc(EVP_des_ede3, nil);
  AssignProc(EVP_des_ede3_cfb64, nil);
  AssignProc(EVP_des_ede3_ofb, nil);
  AssignProc(EVP_desx_cbc, nil);
  AssignProc(EVP_idea_cbc, nil);
  AssignProc(EVP_idea_cfb64, nil);
  AssignProc(EVP_idea_ecb, nil);
  AssignProc(EVP_idea_ofb, nil);
  AssignProc(EVP_rc2_cbc, nil);
  AssignProc(EVP_rc2_cfb64, nil);
  AssignProc(EVP_rc2_ecb, nil);
  AssignProc(EVP_rc2_ofb, nil);
  AssignProc(EVP_rc4, nil);
  AssignProc(EVP_rc4_40, nil);
  AssignProc(BN_new, nil);
  AssignProc(BN_free, nil);
  AssignProc(BN_set_word, nil);
  AssignProc(BN_num_bits, nil);
  AssignProc(BN_bn2bin, nil);
  AssignProc(RSA_new, nil);
  AssignProc(RSA_free, nil);
  AssignProc(RSA_size, nil);
  AssignProc(RSA_public_encrypt, nil);
  AssignProc(RSA_private_decrypt, nil);
  AssignProc(RSA_generate_key_ex, nil);
  AssignProc(RSA_print, nil);
  AssignProc(X509_new, nil);
  AssignProc(X509_free, nil);
  AssignProc(X509_get_pubkey, nil);
  AssignProc(X509_set_version, nil);
  AssignProc(X509_get_version, nil);
  AssignProc(X509_get_serialNumber, nil);
  AssignProc(X509_get_subject_name, nil);
  AssignProc(X509_get_issuer_name, nil);
  AssignProc(X509_set_issuer_name, nil);
  AssignProc(X509_set_pubkey, nil);
  AssignProc(X509_sign, nil);
  AssignProc(X509_gmtime_adj, nil);
  AssignProc(X509_get_notBefore, nil);
  AssignProc(X509_get_notAfter, nil);
  AssignProc(X509_NAME_get_text_by_NID, nil);
  AssignProc(X509_NAME_add_entry_by_txt, nil);
  AssignProc(X509_REQ_new, nil);
  AssignProc(X509_REQ_free, nil);
  AssignProc(X509_REQ_set_version, nil);
  AssignProc(X509_REQ_get_subject_name, nil);
  AssignProc(X509_REQ_set_pubkey, nil);
  AssignProc(X509_REQ_sign, nil);
  AssignProc(ASN1_INTEGER_set, nil);
  AssignProc(ASN1_INTEGER_get, nil);
  AssignProc(ASN1_INTEGER_to_BN, nil);
  AssignProc(ASN1_TIME_print, nil);
  AssignProc(PEM_read_bio_X509, nil);
  AssignProc(PEM_read_bio_PrivateKey, nil);
  AssignProc(PEM_read_bio_RSAPrivateKey, nil);
  AssignProc(PEM_read_bio_PUBKEY, nil);
  AssignProc(PEM_read_bio_RSAPublicKey, nil);
  AssignProc(PEM_write_bio_PrivateKey, nil);
  AssignProc(PEM_write_bio_RSAPrivateKey, nil);
  AssignProc(PEM_write_bio_PUBKEY, nil);
  AssignProc(PEM_write_bio_RSAPublicKey, nil);
  AssignProc(PEM_write_bio_X509, nil);
  AssignProc(PEM_write_bio_X509_REQ, nil);
  AssignProc(X509_STORE_new, nil);
  AssignProc(d2i_PKCS7_bio, nil);
  AssignProc(PKCS7_verify, nil);
  AssignProc(RAND_bytes, nil);
  AssignProc(RAND_status, nil);
  AssignProc(RAND_poll, nil);
  AssignProc(RAND_file_name, nil);
  AssignProc(RAND_load_file, nil);
  AssignProc(RAND_write_file, nil);
end;

function TOpenSSLLoader.Load: Boolean;
var
  VersionNumFn: TOpenSSLVersionNumFn;
begin
  if FLoaded then
    Exit(True);

  FFailedToLoad.Clear;
  FVersionNum := 0;

  FLibHandle := FindLibrary;
  Result := FLibHandle <> 0;
  if not Result then
    Exit;

  VersionNumFn := TOpenSSLVersionNumFn(GetProc('OpenSSL_version_num'));
  if not Assigned(VersionNumFn) then
    VersionNumFn := TOpenSSLVersionNumFn(GetProc('SSLeay'));
  if Assigned(VersionNumFn) then
    FVersionNum := VersionNumFn();
  AssignProc(OpenSSL_version_num, Pointer(VersionNumFn));

  LoadFunctions;

  // Populate the algorithm tables on OpenSSL 1.0 (no-op / not exported later)
  if Assigned(OpenSSL_add_all_algorithms) then
    OpenSSL_add_all_algorithms();
  if Assigned(OpenSSL_add_all_ciphers) then
    OpenSSL_add_all_ciphers();
  if Assigned(OpenSSL_add_all_digests) then
    OpenSSL_add_all_digests();
  if Assigned(ERR_load_crypto_strings) then
    ERR_load_crypto_strings();

  FLoaded := True;
end;

procedure TOpenSSLLoader.Unload;
begin
  if FLibHandle <> 0 then
  begin
    ClearFunctions;
    DoFreeLibrary(FLibHandle);
    FLibHandle := 0;
  end;
  FVersionNum := 0;
  FLoaded := False;
end;

function TOpenSSLLoader.IsLoaded: Boolean;
begin
  Result := FLibHandle <> 0;
end;

initialization
  GOpenSSLLoader := TOpenSSLLoader.Create;

finalization
  GOpenSSLLoader.Free;

end.
