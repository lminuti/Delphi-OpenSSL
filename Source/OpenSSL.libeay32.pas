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
  System.Classes, System.SysUtils, IdSSLOpenSSLHeaders, IdSSLOpenSSL;

var
  X509_get_pubkey : function (a: pX509): pEVP_PKEY; cdecl;
  BIO_free_all : procedure (a: pBIO); cdecl;

//  EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);
//
  PEM_read_bio_PUBKEY : function(bp : PBIO; x : PPEVP_PKEY; cb : ppem_password_cb; u: Pointer) : PEVP_PKEY cdecl;


function LoadOpenSSLLibraryEx :Boolean;

procedure OPENSSL_free(address: pointer);
function BIO_new_from_stream(AStream :TStream) :pBIO;

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

procedure OPENSSL_free(address: pointer);
begin
  CRYPTO_free(address);
end;

function BIO_new_from_stream(AStream :TStream) :pBIO;
var
  Buffer :TBytes;
begin
  SetLength(Buffer, AStream.Size);
  AStream.ReadBuffer(Buffer[0], AStream.Size);
  Result := BIO_new_mem_buf(Buffer, Length(Buffer));
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

    OpenSSL_add_all_algorithms;
    OpenSSL_add_all_ciphers;
    OpenSSL_add_all_digests;
    ERR_load_crypto_strings;
  end;
end;

procedure UnLoadOpenSSLLibraryEx;
begin
  if hSSL <> 0 then
    FreeLibrary(hSSL);
end;


procedure InitializeFuncPointers;
begin
  hSSL := 0;
  X509_get_pubkey := nil;
  BIO_free_all := nil;
  PEM_read_bio_PUBKEY := nil;
end;

initialization
  InitializeFuncPointers;
  //LoadOpenSSLLibrary;

finalization
  UnLoadOpenSSLLibraryEx;

end.
