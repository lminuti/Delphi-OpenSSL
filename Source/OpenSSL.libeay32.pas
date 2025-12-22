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
unit OpenSSL.libeay32;

interface

uses
  System.Classes, System.SysUtils, IdSSLOpenSSLHeaders, IdSSLOpenSSL;

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

  XN_FLAG_COMPAT         = 0;          // Traditional; use old X509_NAME_print
  XN_FLAG_SEP_COMMA_PLUS = (1 shl 16); // RFC2253 ,+
  XN_FLAG_SEP_CPLUS_SPC  = (2 shl 16); // ,+ spaced: more readable
  XN_FLAG_SEP_SPLUS_SPC  = (3 shl 16); // ;+ spaced
  XN_FLAG_SEP_MULTILINE  = (4 shl 16); // One line per field

  XN_FLAG_DN_REV = (1 shl 20);  // Reverse DN order

  // How the field name is shown
  XN_FLAG_FN_MASK = ($3 shl 21);
  XN_FLAG_FN_SN   = 0;           // Object short name
  XN_FLAG_FN_LN   = (1 shl 21);  // Object long name
  XN_FLAG_FN_OID  = (2 shl 21);  // Always use OIDs
  XN_FLAG_FN_NONE = (3 shl 21);  // No field names

  XN_FLAG_SPC_EQ  = (1 shl 23);  // Put spaces round '='

  // This determines if we dump fields we don't recognise: RFC2253 requires this.
  XN_FLAG_DUMP_UNKNOWN_FIELDS = (1 shl 24);

  XN_FLAG_FN_ALIGN = (1 shl 25); // Align field names to 20 characters

  XN_FLAG_RFC2253 = ASN1_STRFLGS_RFC2253 or XN_FLAG_SEP_COMMA_PLUS or XN_FLAG_DN_REV or XN_FLAG_FN_SN or XN_FLAG_DUMP_UNKNOWN_FIELDS;

SN_commonName = 'CN';
  LN_commonName = 'commonName';
  NID_commonName = 13;

  SN_surname = 'SN';
  LN_surname = 'surname';
  NID_surname = 100;

  LN_serialNumber = 'serialNumber';
  NID_serialNumber = 105;

  SN_countryName = 'C';
  LN_countryName = 'countryName';
  NID_countryName = 14;

  SN_localityName = 'L';
  LN_localityName = 'localityName';
  NID_localityName = 15;

  SN_stateOrProvinceName = 'ST';
  LN_stateOrProvinceName = 'stateOrProvinceName';
  NID_stateOrProvinceName = 16;

  SN_streetAddress = 'street';
  LN_streetAddress = 'streetAddress';
  NID_streetAddress = 660;

  SN_organizationName = 'O';
  LN_organizationName = 'organizationName';
  NID_organizationName = 17;

  SN_organizationalUnitName = 'OU';
  LN_organizationalUnitName = 'organizationalUnitName';
  NID_organizationalUnitName = 18;

  SN_title = 'title';
  LN_title = 'title';
  NID_title = 106;

  LN_description = 'description';
  NID_description = 107;

  LN_searchGuide = 'searchGuide';
  NID_searchGuide = 859;
  LN_businessCategory = 'businessCategory';
  NID_businessCategory = 860;

  LN_postalAddress = 'postalAddress';
  NID_postalAddress = 861;

  LN_postalCode = 'postalCode';
  NID_postalCode = 661;

  LN_postOfficeBox = 'postOfficeBox';
  NID_postOfficeBox = 862;

  LN_physicalDeliveryOfficeName = 'physicalDeliveryOfficeName';
  NID_physicalDeliveryOfficeName = 863;

  LN_telephoneNumber = 'telephoneNumber';
  NID_telephoneNumber = 864;

  LN_telexNumber = 'telexNumber';
  NID_telexNumber = 865;

  LN_teletexTerminalIdentifier = 'teletexTerminalIdentifier';
  NID_teletexTerminalIdentifier = 866;

  LN_facsimileTelephoneNumber = 'facsimileTelephoneNumber';
  NID_facsimileTelephoneNumber = 867;

  LN_x121Address = 'x121Address';
  NID_x121Address = 868;

  LN_internationaliSDNNumber = 'internationaliSDNNumber';
  NID_internationaliSDNNumber = 869;

  LN_registeredAddress = 'registeredAddress';
  NID_registeredAddress = 870;

  LN_destinationIndicator = 'destinationIndicator';
  NID_destinationIndicator = 871;

  LN_preferredDeliveryMethod = 'preferredDeliveryMethod';
  NID_preferredDeliveryMethod = 872;

  LN_presentationAddress = 'presentationAddress';
  NID_presentationAddress = 873;

  LN_supportedApplicationContext = 'supportedApplicationContext';
  NID_supportedApplicationContext = 874;

  SN_member = 'member';
  NID_member = 875;

  SN_owner = 'owner';
  NID_owner = 876;

  LN_roleOccupant = 'roleOccupant';
  NID_roleOccupant = 877;

  SN_seeAlso = 'seeAlso';
  NID_seeAlso = 878;

  LN_userPassword = 'userPassword';
  NID_userPassword = 879;

  LN_userCertificate = 'userCertificate';
  NID_userCertificate = 880;

  LN_cACertificate = 'cACertificate';
  NID_cACertificate = 881;

  LN_authorityRevocationList = 'authorityRevocationList';
  NID_authorityRevocationList = 882;

  LN_certificateRevocationList = 'certificateRevocationList';
  NID_certificateRevocationList = 883;

  LN_crossCertificatePair = 'crossCertificatePair';
  NID_crossCertificatePair = 884;

  SN_name = 'name';
  LN_name = 'name';
  NID_name = 173;

  SN_givenName = 'GN';
  LN_givenName = 'givenName';
  NID_givenName = 99;

  SN_initials = 'initials';
  LN_initials = 'initials';
  NID_initials = 101;

  LN_generationQualifier = 'generationQualifier';
  NID_generationQualifier = 509;

  LN_x500UniqueIdentifier = 'x500UniqueIdentifier';
  NID_x500UniqueIdentifier = 503;

  SN_dnQualifier = 'dnQualifier';
  LN_dnQualifier = 'dnQualifier';
  NID_dnQualifier = 174;

  LN_enhancedSearchGuide = 'enhancedSearchGuide';
  NID_enhancedSearchGuide = 885;

  LN_protocolInformation = 'protocolInformation';
  NID_protocolInformation = 886;

  LN_distinguishedName = 'distinguishedName';
  NID_distinguishedName = 887;

  LN_uniqueMember = 'uniqueMember';
  NID_uniqueMember = 888;

  LN_houseIdentifier = 'houseIdentifier';
  NID_houseIdentifier = 889;

  LN_supportedAlgorithms = 'supportedAlgorithms';
  NID_supportedAlgorithms = 890;

  LN_deltaRevocationList = 'deltaRevocationList';
  NID_deltaRevocationList = 891;

  SN_dmdName = 'dmdName';
  NID_dmdName = 892;

  LN_pseudonym = 'pseudonym';
  NID_pseudonym = 510;

  SN_role = 'role';
  LN_role = 'role';
  NID_role = 400;

  LN_organizationIdentifier = 'organizationIdentifier';
  NID_organizationIdentifier = 1089;

  SN_countryCode3c = 'c3';
  LN_countryCode3c = 'countryCode3c';
  NID_countryCode3c = 1090;

  SN_countryCode3n = 'n3';
  LN_countryCode3n = 'countryCode3n';
  NID_countryCode3n = 1091;

  LN_dnsName = 'dnsName';
  NID_dnsName = 1092;

  SN_X500algorithms = 'X500algorithms';
  LN_X500algorithms = 'directory services - algorithms';
  NID_X500algorithms = 378;

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
  X509_STORE_new: function(): PX509_STORE; cdecl;
  X509_NAME_print_ex: function(out: PBIO; nm: PX509_NAME; indent: Integer; flags: cardinal): Integer; cdecl;

  RAND_bytes : function (buf: PAnsiChar; num: Integer): Integer cdecl;
  RAND_pseudo_bytes : function (buf: PAnsiChar; num: Integer): Integer cdecl;
  RAND_status: function: Integer cdecl;
  RAND_poll: function: Integer cdecl;
  RAND_file_name: function (buf: PAnsiChar; num: Integer): PAnsiChar cdecl;
  RAND_load_file: function (filename: PAnsiChar; max_bytes: Integer): Integer; cdecl;
  RAND_write_file: function (filename: PAnsiChar): Integer cdecl;

  X509_REQ_set_version: function(x: pX509_REQ; version: Integer): Integer; cdecl;
  X509_NAME_get_text_by_NID: function (name: PX509_NAME; nid: Integer; buf: PAnsiChar; len: Integer): Integer; cdecl;

  ASN1_TIME_print: function (bp: PBIO; s: PASN1_TIME): Integer; cdecl;
  ASN1_TIME_print_ex: function (bp: PBIO; tm: PASN1_TIME; flags: cardinal): Integer; cdecl;

  BN_num_bits: function (a: PBIGNUM): Integer; cdecl;
  BN_bn2bin : function (a: PBIGNUM; &to: PByte): Integer; cdecl;

function BIO_get_mem_data(b : PBIO; pp : Pointer) : Integer;
function BIO_to_string(b : PBIO; Encoding: TEncoding): string; overload;
function BIO_to_string(b : PBIO): string; overload;

function BN_num_bytes(a: PBIGNUM): Integer;

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

function BN_num_bytes(a: PBIGNUM): Integer;
begin
  Result := (BN_num_bits(a)+7) div 8;
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
  X509_STORE_new := nil;
  RAND_bytes := nil;
  RAND_pseudo_bytes := nil;
  RAND_status := nil;
  RAND_poll := nil;
  RAND_file_name := nil;
  RAND_load_file := nil;
  RAND_write_file := nil;
  X509_REQ_set_version := nil;
  X509_NAME_print_ex := nil;
  X509_NAME_get_text_by_NID := nil;

  ASN1_TIME_print := nil;
  ASN1_TIME_print_ex := nil;

  BN_bn2bin := nil;
  BN_num_bits := nil;
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
    X509_STORE_new := GetProcAddress(hSSL, 'X509_STORE_new');
    X509_NAME_print_ex := GetProcAddress(hSSL, 'X509_NAME_print_ex');
    RAND_bytes := GetProcAddress(hSSL, 'RAND_bytes');
    RAND_pseudo_bytes := GetProcAddress(hSSL, 'RAND_pseudo_bytes');
    RAND_status := GetProcAddress(hSSL, 'RAND_status');
    RAND_poll := GetProcAddress(hSSL, 'RAND_poll');
    RAND_file_name := GetProcAddress(hSSL, 'RAND_file_name');
    RAND_load_file := GetProcAddress(hSSL, 'RAND_load_file');
    RAND_write_file := GetProcAddress(hSSL, 'RAND_write_file');
    X509_REQ_set_version := GetProcAddress(hSSL, 'X509_REQ_set_version');
    X509_NAME_get_text_by_NID := GetProcAddress(hSSL, 'X509_NAME_get_text_by_NID');

    ASN1_TIME_print := GetProcAddress(hSSL, 'ASN1_TIME_print');
    ASN1_TIME_print_ex := GetProcAddress(hSSL, 'ASN1_TIME_print_ex');

    BN_bn2bin := GetProcAddress(hSSL, 'BN_bn2bin');
    BN_num_bits := GetProcAddress(hSSL, 'BN_num_bits');

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
