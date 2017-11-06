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

// enc - symmetric cipher routines
// https://www.openssl.org/docs/manmaster/apps/enc.html

unit OpenSSL.SMIMEUtils;

interface

uses
  System.Classes, System.SysUtils,
  OpenSSL.libeay32, OpenSSL.Core, IdSSLOpenSSLHeaders;

type
  TSMIMEUtil = class(TOpenSLLBase)
  public
    function Decrypt(InputStream, OutputStream :TStream; Verify, NoVerify: Boolean): Integer;
  end;

implementation

{ TSMIMEUtil }

function TSMIMEUtil.Decrypt(InputStream, OutputStream: TStream; Verify, NoVerify: Boolean): Integer;
var
  LInput, LOutput, LContent: PBIO;
  LPKCS7: PPKCS7;
  LStore: PX509_STORE;
  LCerts: PSTACK_OF_X509;
  LFlags, LOutputLen: Integer;
  LOutputBuffer, LInputBuffer: TBytes;
begin

  Result := 0;
  LFlags := 0;
  if NoVerify then
    LFlags := PKCS7_NOVERIFY;
  LContent := nil;
  LCerts := nil;
  LInput := nil;
  LOutput := nil;
  LStore := X509_STORE_new();
  try
    SetLength(LInputBuffer, InputStream.Size);
    InputStream.ReadBuffer(LInputBuffer[0], InputStream.Size);

    LInput := BIO_new_mem_buf(LInputBuffer, InputStream.Size);
    if not Assigned(LInput) then
      RaiseOpenSSLError('BIO_new_file');

    LPKCS7 := nil;
    LPKCS7 := d2i_PKCS7_bio(LInput, LPKCS7);

    if not Assigned(LPKCS7) then
      RaiseOpenSSLError('FSMIME_read_PKCS7');

    LOutput := BIO_new(BIO_s_mem());
    if not Assigned(LOutput) then
      RaiseOpenSSLError('BIO_new');

    if Verify then
    begin
      Result := PKCS7_verify(LPKCS7, LCerts, LStore, LContent, LOutput, LFlags);

      if Assigned(LOutput) and Assigned(OutputStream) then
      begin
        LOutputLen := LOutput.num_write;
        SetLength(LOutputBuffer, LOutputLen);
        BIO_read(LOutput, LOutputBuffer, LOutputLen);

        OutputStream.WriteBuffer(LOutputBuffer, LOutputLen);
      end;
    end;
  finally
    BIO_free(LInput);
    BIO_free(LOutput);
    BIO_free(LContent);
  end;
end;

end.
