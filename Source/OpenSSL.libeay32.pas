{******************************************************************************}
{                                                                              }
{  Delphi OPENSSL Library                                                      }
{  Copyright (c) 2016 Luca Minuti                                              }
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
unit OpenSSL.libeay32;

interface

uses
  System.Classes, System.SysUtils, OpenSSL.CMSHeaders, IdSSLOpenSSLHeaders, IdSSLOpenSSL;

const
  { S/MIME related flags }
  PKCS7_TEXT              = $1;
  PKCS7_NOCERTS           = $2;
  PKCS7_NOSIGS            = $4;
  PKCS7_NOCHAIN           = $8;
  PKCS7_NOINTERN          = $10;
  PKCS7_NOVERIFY          = $20;
  PKCS7_DETACHED          = $40;
  PKCS7_BINARY            = $80;
  PKCS7_NOATTR            = $100;
  PKCS7_NOSMIMECAP        = $200;
  PKCS7_NOOLDMIMETYPE     = $400;
  PKCS7_CRLFEOL           = $800;
  PKCS7_STREAM            = $1000;
  PKCS7_NOCRL             = $2000;
  PKCS7_PARTIAL           = $4000;
  PKCS7_REUSE_DIGEST      = $8000;
  PKCS7_NO_DUAL_CONTENT   = $10000;

  { Flags: for compatibility with older code }
  SMIME_TEXT      = PKCS7_TEXT;
  SMIME_NOCERTS   = PKCS7_NOCERTS;
  SMIME_NOSIGS    = PKCS7_NOSIGS;
  SMIME_NOCHAIN   = PKCS7_NOCHAIN;
  SMIME_NOINTERN  = PKCS7_NOINTERN;
  SMIME_NOVERIFY  = PKCS7_NOVERIFY;
  SMIME_DETACHED  = PKCS7_DETACHED;
  SMIME_BINARY    = PKCS7_BINARY;
  SMIME_NOATTR    = PKCS7_NOATTR;

var
  X509_get_pubkey : function (a: pX509): pEVP_PKEY; cdecl;

  EVP_BytesToKey : function (cipher_type: PEVP_CIPHER; md: PEVP_MD; salt: PByte; data: PByte; datal: integer; count: integer; key: PByte; iv: PByte): integer; cdecl;
  EVP_DecryptUpdate : function (ctx: PEVP_CIPHER_CTX; data_out: PByte; var outl: integer; data_in: PByte; inl: integer): integer; cdecl;
  EVP_DecryptFinal : function (ctx: PEVP_CIPHER_CTX; data_out: PByte; var outl: integer): integer; cdecl;
  EVP_DecryptFinal_ex : function(ctx : PEVP_CIPHER_CTX; outm: PByte; var outl : integer) : integer cdecl = nil;

  BIO_free_all : procedure (a: pBIO); cdecl;
  BIO_push : function (b :pBIO; append :pBIO) :pBIO; cdecl;
  BIO_pop : function (b :pBIO) :pBIO; cdecl;
  BIO_set_next : function (b :pBIO; next :pBIO) :pBIO; cdecl;
  RSA_print : function (bp :pBIO; x: pRSA; offset: Integer): Integer; cdecl;

//  EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);
//
  PEM_read_bio_PUBKEY : function(bp : PBIO; x : PPEVP_PKEY; cb : ppem_password_cb; u: Pointer) : PEVP_PKEY cdecl;
  PEM_write_bio_PUBKEY : function(bp : PBIO; x : PEVP_PKEY) : PEVP_PKEY cdecl;

  d2i_PKCS7_bio: function(bp: PBIO; var pkcs7: PPKCS7): PPKCS7; cdecl;
  PKCS7_verify: function(p7: PPKCS7; certs: PSTACK_OF_X509; store: PX509_STORE; indata, outdata: PBIO; flags: Integer): Integer cdecl;
  d2i_CMS_bio: function(bp: PBIO; var cms: PCMS_ContentInfo): PCMS_ContentInfo; cdecl;
  CMS_verify: function(cms: PCMS_ContentInfo; certs: PSTACK_OF_X509; store: PX509_STORE; indata, outdata: PBIO; flags: Integer): Integer cdecl;
  X509_STORE_new: function(): PX509_STORE; cdecl;

  RAND_bytes : function (buf: PAnsiChar; num: Integer): Integer cdecl;
  RAND_pseudo_bytes : function (buf: PAnsiChar; num: Integer): Integer cdecl;
  RAND_status: function: Integer cdecl;
  RAND_poll: function: Integer cdecl;
  RAND_file_name: function (buf: PAnsiChar; num: Integer): PAnsiChar cdecl;
  RAND_load_file: function (filename: PAnsiChar; max_bytes: Integer): Integer cdecl;
  RAND_write_file: function (filename: PAnsiChar): Integer;

function BIO_get_mem_data(b : PBIO; pp : Pointer) : Integer;
function BIO_to_string(b : PBIO; Encoding: TEncoding): string; overload;
function BIO_to_string(b : PBIO): string; overload;

function LoadOpenSSLLibraryEx :Boolean;
procedure UnLoadOpenSSLLibraryEx;

procedure OPENSSL_free(address: pointer);

implementation

uses
  Winapi.Windows;

const
  LIBEAY_DLL_NAME = 'libeay32.dll';

var
  hSSL :HMODULE;


//function X509_get_pubkey(a: pX509): pEVP_PKEY; cdecl; external LIBEAY_DLL_NAME;
//
//procedure BIO_free_all(a: pBIO); cdecl; external LIBEAY_DLL_NAME;

function BIO_get_mem_data(b : PBIO; pp : Pointer) : Integer;
begin
  Result := BIO_ctrl(b,BIO_CTRL_INFO,0,pp);
end;

function BIO_to_string(b : PBIO; Encoding: TEncoding): string;
const
  BuffSize = 1024;
var
  Buffer: TBytes;
begin
  Result := '';
  SetLength(Buffer, BuffSize);
  while BIO_read(b, buffer, BuffSize) > 0 do
  begin
    Result := Result + Encoding.GetString(Buffer);
  end;
end;

function BIO_to_string(b : PBIO): string; overload;
begin
  Result := BIO_to_string(b, TEncoding.ANSI);
end;

procedure OPENSSL_free(address: pointer);
begin
  CRYPTO_free(address);
end;

procedure ResetFuncPointers;
begin
  hSSL := 0;
  X509_get_pubkey := nil;
  BIO_free_all := nil;
  PEM_read_bio_PUBKEY := nil;
  PEM_write_bio_PUBKEY := nil;
  EVP_BytesToKey := nil;
  EVP_DecryptUpdate := nil;
  EVP_DecryptFinal := nil;
  EVP_DecryptFinal_ex := nil;
  BIO_push := nil;
  BIO_pop := nil;
  BIO_set_next := nil;

  RSA_print := nil;

  d2i_PKCS7_bio := nil;
  PKCS7_verify := nil;
  d2i_CMS_bio := nil;
  CMS_verify := nil;
  X509_STORE_new := nil;
  RAND_bytes := nil;
  RAND_pseudo_bytes := nil;
  RAND_status := nil;
  RAND_poll := nil;
  RAND_file_name := nil;
  RAND_load_file := nil;
  RAND_write_file := nil;
end;

function LoadOpenSSLLibraryEx :Boolean;
begin
  if hSSL <> 0 then
    Exit(True);

  Result := IdSSLOpenSSL.LoadOpenSSLLibrary;
  if Result then
  begin
    hSSL := LoadLibrary(LIBEAY_DLL_NAME);
    if hSSL = 0 then
      Exit(False);
    X509_get_pubkey := GetProcAddress(hSSL, 'X509_get_pubkey');
    BIO_free_all := GetProcAddress(hSSL, 'BIO_free_all');
    PEM_read_bio_PUBKEY := GetProcAddress(hSSL, 'PEM_read_bio_PUBKEY');
    PEM_write_bio_PUBKEY := GetProcAddress(hSSL, 'PEM_write_bio_PUBKEY');
    EVP_BytesToKey := GetProcAddress(hSSL, 'EVP_BytesToKey');
    EVP_DecryptUpdate := GetProcAddress(hSSL, 'EVP_DecryptUpdate');
    EVP_DecryptFinal := GetProcAddress(hSSL, 'EVP_DecryptFinal');
    EVP_DecryptFinal_ex := GetProcAddress(hSSL, 'EVP_DecryptFinal_ex');
    BIO_push := GetProcAddress(hSSL, 'BIO_push');
    BIO_pop := GetProcAddress(hSSL, 'BIO_pop');
    BIO_set_next := GetProcAddress(hSSL, 'BIO_set_next');

    RSA_print := GetProcAddress(hSSL, 'RSA_print');

    d2i_PKCS7_bio := GetProcAddress(hSSL, 'd2i_PKCS7_bio');
    PKCS7_verify := GetProcAddress(hSSL, 'PKCS7_verify');
    d2i_CMS_bio := GetProcAddress(hSSL, 'd2i_CMS_bio');
    CMS_verify := GetProcAddress(hSSL, 'CMS_verify');
    X509_STORE_new := GetProcAddress(hSSL, 'X509_STORE_new');
    RAND_bytes := GetProcAddress(hSSL, 'RAND_bytes');
    RAND_pseudo_bytes := GetProcAddress(hSSL, 'RAND_pseudo_bytes');
    RAND_status := GetProcAddress(hSSL, 'RAND_status');
    RAND_poll := GetProcAddress(hSSL, 'RAND_poll');
    RAND_file_name := GetProcAddress(hSSL, 'RAND_file_name');
    RAND_load_file := GetProcAddress(hSSL, 'RAND_load_file');
    RAND_write_file := GetProcAddress(hSSL, 'RAND_write_file');

    OpenSSL_add_all_algorithms;
    OpenSSL_add_all_ciphers;
    OpenSSL_add_all_digests;
    ERR_load_crypto_strings;
  end;
end;

procedure UnLoadOpenSSLLibraryEx;
begin
  if hSSL <> 0 then
  begin
    FreeLibrary(hSSL);
    ResetFuncPointers;
  end;
end;

initialization
  ResetFuncPointers;
  //LoadOpenSSLLibrary;

finalization
  UnLoadOpenSSLLibraryEx;

end.
