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

unit OpenSSL.EncUtils;

interface

uses
  System.Classes, System.SysUtils, System.AnsiStrings, OpenSSL.libeay32,
  OpenSSL.Core, IdSSLOpenSSLHeaders;

type
  TEncUtil = class(TOpenSLLBase)
  private
    FPassphrase: TBytes;
    FBase64: Boolean;
    function GetPassphrase: string;
    procedure SetPassphrase(const Value: string);
  public
    // will be encoded in UTF8
    property Passphrase :string read GetPassphrase write SetPassphrase;
    property BinaryPassphrase :TBytes read FPassphrase write FPassphrase;

    // Apply a further base64 encoding to the encrypted buffer
    property UseBase64 :Boolean read FBase64 write FBase64;

    procedure Encrypt(InputStream :TStream; OutputStream :TStream); overload;
    procedure Encrypt(const InputFileName, OutputFileName :TFileName); overload;
    procedure Decrypt(InputStream :TStream; OutputStream :TStream); overload;
    procedure Decrypt(const InputFileName, OutputFileName :TFileName); overload;
  end;

implementation

{ TEncUtil }

procedure TEncUtil.Decrypt(InputStream, OutputStream: TStream);
var
  Context :PEVP_CIPHER_CTX;
  Key :TBytes;
  InitVector :TBytes;

  InputBuffer :TBytes;
  OutputLen :Integer;
  OutputBuffer :TBytes;
  Base64Buffer :TBytes;

  Cipher: PEVP_CIPHER;
  Salt :TBytes;
  BuffStart :Integer;
  InputStart :Integer;
begin
  Cipher := EVP_aes_256_cbc();

  if FBase64 then
  begin
    SetLength(Base64Buffer, InputStream.Size);
    InputStream.ReadBuffer(Base64Buffer[0], InputStream.Size);
    InputBuffer := Base64Decode(Base64Buffer);
  end
  else
  begin
    SetLength(InputBuffer, InputStream.Size);
    InputStream.ReadBuffer(InputBuffer[0], InputStream.Size);
  end;

  SetLength(Salt, SALT_SIZE);
  // First read the magic text and the Salt - if any
  if (AnsiString(TEncoding.ASCII.GetString(InputBuffer, 0, SALT_MAGIC_LEN)) = SALT_MAGIC) then
  begin
    Move(InputBuffer[SALT_MAGIC_LEN], Salt[0], SALT_SIZE);
    EVP_GetKeyIV(FPassphrase, Cipher, Salt, Key, InitVector);
    InputStart := SALT_MAGIC_LEN + SALT_SIZE;
  end
  else
  begin
    EVP_GetKeyIV(FPassphrase, Cipher, nil, Key, InitVector);
    InputStart := 0;
  end;

  Context := EVP_CIPHER_CTX_new();
  if Context = nil then
    RaiseOpenSSLError('Cannot initialize context');

  try

    if EVP_DecryptInit_ex(Context, Cipher, nil, @Key[0], @InitVector[0]) <> 1 then
      RaiseOpenSSLError('Cannot initialize decryption process');

    SetLength(OutputBuffer, InputStream.Size);
    BuffStart := 0;
    if OpenSSL.libeay32.EVP_DecryptUpdate(Context, @OutputBuffer[BuffStart], OutputLen, @InputBuffer[InputStart], Length(InputBuffer) - InputStart) <> 1 then
      RaiseOpenSSLError('Cannot decrypt');
    Inc(BuffStart, OutputLen);

    if OpenSSL.libeay32.EVP_DecryptFinal_ex(Context, @OutputBuffer[BuffStart], OutputLen) <> 1 then
      RaiseOpenSSLError('Cannot finalize decryption process');
    Inc(BuffStart, OutputLen);

    if BuffStart > 0 then
      OutputStream.WriteBuffer(OutputBuffer[0], BuffStart);

  finally
    EVP_CIPHER_CTX_free(Context);
  end;
end;

procedure TEncUtil.Encrypt(InputStream, OutputStream: TStream);
var
  Context :PEVP_CIPHER_CTX;

  Key :TBytes;
  InitVector :TBytes;
  InputBuffer :TBytes;
  OutputLen :Integer;
  OutputBuffer :TBytes;
  Base64Buffer :TBytes;
  Salt :TBytes;

  cipher: PEVP_CIPHER;
  BlockSize :Integer;
  BuffStart :Integer;
  WriteSalt :Boolean;
begin
  WriteSalt := True;
  BuffStart := 0;

  cipher := EVP_aes_256_cbc();
  salt := EVP_GetSalt;
  EVP_GetKeyIV(FPassphrase, cipher, salt, key, InitVector);

  SetLength(InputBuffer, InputStream.Size);
  InputStream.ReadBuffer(InputBuffer[0], InputStream.Size);

  Context := EVP_CIPHER_CTX_new();
  if Context = nil then
    RaiseOpenSSLError('Cannot initialize context');

  try
    if EVP_EncryptInit_ex(Context, cipher, nil, @Key[0], @InitVector[0]) <> 1 then
      RaiseOpenSSLError('Cannot initialize encryption process');

    BlockSize := EVP_CIPHER_CTX_block_size(Context);
    if WriteSalt then
    begin
      SetLength(OutputBuffer, Length(InputBuffer) + BlockSize + SALT_MAGIC_LEN + PKCS5_SALT_LEN);
      Move(PAnsiChar(SALT_MAGIC)^, OutputBuffer[BuffStart], SALT_MAGIC_LEN);
      Inc(BuffStart, SALT_MAGIC_LEN);
      Move(salt[0], OutputBuffer[BuffStart], PKCS5_SALT_LEN);
      Inc(BuffStart, PKCS5_SALT_LEN);
    end
    else
      SetLength(OutputBuffer, Length(InputBuffer) + BlockSize);

    if EVP_EncryptUpdate(Context, @OutputBuffer[BuffStart], @OutputLen, @InputBuffer[0], Length(InputBuffer)) <> 1 then
      RaiseOpenSSLError('Cannot encrypt');
    Inc(BuffStart, OutputLen);

    if EVP_EncryptFinal_ex(Context, @OutputBuffer[BuffStart], @OutputLen) <> 1 then
      RaiseOpenSSLError('Cannot finalize encryption process');
    Inc(BuffStart, OutputLen);
    SetLength(OutputBuffer, BuffStart);

    if BuffStart > 0 then
    begin
      if FBase64 then
      begin
        Base64Buffer := Base64Encode(OutputBuffer);
        OutputStream.WriteBuffer(Base64Buffer[0], Length(Base64Buffer));
      end
      else
        OutputStream.WriteBuffer(OutputBuffer[0], BuffStart);
    end;

  finally
    EVP_CIPHER_CTX_free(Context);
  end;
end;

procedure TEncUtil.Encrypt(const InputFileName, OutputFileName: TFileName);
var
  InputFile, OutputFile :TStream;
begin
  InputFile := TFileStream.Create(InputFileName, fmOpenRead);
  try
    OutputFile := TFileStream.Create(OutputFileName, fmCreate);
    try
      Encrypt(InputFile, OutputFile);
    finally
      OutputFile.Free;
    end;
  finally
    InputFile.Free;
  end;
end;

function TEncUtil.GetPassphrase: string;
begin
  Result := TEncoding.UTF8.GetString(FPassphrase);
end;

procedure TEncUtil.SetPassphrase(const Value: string);
begin
  FPassphrase := TEncoding.UTF8.GetBytes(Value);
end;

procedure TEncUtil.Decrypt(const InputFileName, OutputFileName: TFileName);
var
  InputFile, OutputFile :TStream;
begin
  InputFile := TFileStream.Create(InputFileName, fmOpenRead);
  try
    OutputFile := TFileStream.Create(OutputFileName, fmCreate);
    try
      Decrypt(InputFile, OutputFile);
    finally
      OutputFile.Free;
    end;
  finally
    InputFile.Free;
  end;
end;

end.
