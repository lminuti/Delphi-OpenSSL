{******************************************************************************}
{                                                                              }
{  Delphi OPENSSL Library                                                      }
{  Copyright (c) 2016 Luca Minuti                                              }
{  https://github.com/lminuti/Delphi-OpenSSL                                   }
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
  OpenSSL.libeay32, OpenSSL.Core, OpenSSL.CMSHeaders, IdSSLOpenSSLHeaders;

type
  TSMIMEUtil = class(TOpenSLLBase)
  public
    function Decrypt(InputStream, OutputStream: TStream; const CAfile: AnsiString; Verify, NoVerify: Boolean): Boolean;
    class function Extract(InputStream, OutputStream: TStream): Boolean;
    class function Verify(InputStream, OutputStream: TStream; const CAfile: AnsiString = ''): Boolean;
  end;

implementation

{ TSMIMEUtil }

function TSMIMEUtil.Decrypt(InputStream, OutputStream: TStream;
  const CAfile: AnsiString; Verify, NoVerify: Boolean): Boolean;
const
  BSIZE = 1024*8;
var
  LInput, LOutput, LContent: PBIO;
  LCMS_ContentInfo: PCMS_ContentInfo;
  LStore: PX509_STORE;
  LCerts: PSTACK_OF_X509;
  LFlags, LOutputLen: Integer;
  LOutputBuffer, LInputBuffer: TBytes;
begin
  Result := False;

  if not Assigned(InputStream)
    then Exit; //raise?

  LFlags := 0;
  if NoVerify
    then LFlags := CMS_NOVERIFY;
  LContent := nil;
  LCerts := nil;
  LInput := nil;
  LOutput := nil;
  LStore := nil;
  try
    SetLength(LInputBuffer, InputStream.Size);
    InputStream.ReadBuffer(LInputBuffer[0], InputStream.Size);

    LInput := BIO_new_mem_buf(LInputBuffer, InputStream.Size);
    if not Assigned(LInput) then
      RaiseOpenSSLError('BIO_new_file');

    LCMS_ContentInfo := nil;
    LCMS_ContentInfo := d2i_CMS_bio(LInput, LCMS_ContentInfo);

    if not Assigned(LCMS_ContentInfo) then
      RaiseOpenSSLError('FSMIME_read_PKCS7');

    LOutput := BIO_new(BIO_s_mem());
    if not Assigned(LOutput) then
      RaiseOpenSSLError('BIO_new');

    if Verify then
    begin
      LStore := X509_STORE_new();
      if (not NoVerify)and(CAfile <> '') then
      begin
        if X509_STORE_load_locations(LStore, PAnsiChar(CAfile), nil) = 0
          then RaiseOpenSSLError('X509_STORE_load_locations');
      end;

      if CMS_verify(LCMS_ContentInfo, LCerts, LStore, LContent, LOutput, LFlags) > 0 then
      begin
        LOutputLen := LOutput.num_write;
        if LOutputLen < 0
          then RaiseOpenSSLError('CMS_verify');
        if LOutputLen = 0
          then Exit;
        SetLength(LOutputBuffer, LOutputLen);
        BIO_read(LOutput, LOutputBuffer, LOutputLen);
        if Assigned(OutputStream)
          then OutputStream.WriteBuffer(LOutputBuffer, LOutputLen);
        Result := True;
      end;
    end else
    begin
      LContent := CMS_dataInit(LCMS_ContentInfo, nil);
      if Assigned(LContent) then
      begin
        SetLength(LOutputBuffer, BSIZE);
        while ((BIO_pending(LContent) > 0)or(BIO_eof(LContent) = 0)) do
        begin
          LOutputLen := BIO_read(LContent, LOutputBuffer, BSIZE);
          if LOutputLen < 0
            then RaiseOpenSSLError('BIO_read');
          if LOutputLen = 0
            then Break;
          if Assigned(OutputStream)
            then OutputStream.WriteBuffer(LOutputBuffer, LOutputLen);
          Result := True;
        end;
      end;
    end;
  finally
    BIO_free(LInput);
    BIO_free(LOutput);
    BIO_free(LContent);
    CMS_free(LCMS_ContentInfo);
    X509_STORE_free(LStore);
  end;
end;

class function TSMIMEUtil.Extract(InputStream, OutputStream: TStream): Boolean;
begin
  try
    with TSMIMEUtil.Create do
    try
      Result := Decrypt(InputStream, OutputStream, '', False, False);
    finally
      Free;
    end;
  except
    Result := False;
  end;
end;

class function TSMIMEUtil.Verify(InputStream, OutputStream: TStream;
  const CAfile: AnsiString): Boolean;
begin
  try
    with TSMIMEUtil.Create do
    try
      Result := Decrypt(InputStream, OutputStream, CAfile, True, CAfile = '');
    finally
      Free;
    end;
  except
    Result := False;
  end;
end;

end.
