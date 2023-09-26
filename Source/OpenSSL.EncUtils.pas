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
  System.Classes, System.SysUtils, System.AnsiStrings, Generics.Collections,
  OpenSSL.libeay32, OpenSSL.Core, IdSSLOpenSSLHeaders;

type
  TCipherName = string;

  TCipherProc = function : PEVP_CIPHER cdecl;

  TCipherInfo = record
    Name :TCipherName;
    Proc :TCipherProc;
  end;

  TCipherList = class(TThreadList<TCipherInfo>)
  public
    function Count :Integer;
    function GetProc(const Name :TCipherName) :TCipherProc;
  end;

  TPassphraseType = (ptNone, ptPassword, ptKeys);

  TPassphrase = record
  private
    FType: TPassphraseType;
    FValue: TBytes;
    FKey: TBytes;
    FInitVector: TBytes;
  public
    class operator Implicit(const Value: string): TPassphrase;
    class operator Implicit(const Value: TBytes): TPassphrase;
    constructor Create(const Key, InitVector: TBytes); overload;
    constructor Create(const Password: string; Encoding: TEncoding); overload;
  end;

  TEncUtil = class(TOpenSLLBase)
  private
    class var
    FCipherList :TCipherList;
    class constructor Create;
    class destructor Destroy;
  private
    FPassphrase: TPassphrase;
    FBase64: Boolean;
    FCipherProc: TCipherProc;
    FCipher: TCipherName;
    procedure SetCipher(const Value: TCipherName);
  public
    class procedure RegisterCipher(const Name :TCipherName; Proc :TCipherProc);
    class procedure RegisterDefaultCiphers;
    class procedure SupportedCiphers(Ciphers :TStrings);
  public
    constructor Create; override;
    // will be encoded in UTF8
    property Passphrase :TPassphrase read FPassphrase write FPassphrase;

    // Encryption algorithm
    property Cipher :TCipherName read FCipher write SetCipher;

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
  if Assigned(FCipherProc) then
    Cipher := FCipherProc()
  else
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

  if FPassphrase.FType = ptPassword then
  begin
    SetLength(Salt, SALT_SIZE);
    if (AnsiString(TEncoding.ASCII.GetString(InputBuffer, 0, SALT_MAGIC_LEN)) = SALT_MAGIC) then
    begin
      if Length(FPassphrase.FValue) = 0 then
        raise EOpenSSLError.Create('Password needed');

      Move(InputBuffer[SALT_MAGIC_LEN], Salt[0], SALT_SIZE);
      EVP_GetKeyIV(FPassphrase.FValue, Cipher, Salt, Key, InitVector);
      InputStart := SALT_MAGIC_LEN + SALT_SIZE;
    end
    else
    begin
      EVP_GetKeyIV(FPassphrase.FValue, Cipher, nil, Key, InitVector);
      InputStart := 0;
    end;
  end
  else if FPassphrase.FType = ptKeys then
  begin
    Key := FPassphrase.FKey;
    InitVector := FPassphrase.FInitVector;
    InputStart := 0;
  end
  else
    raise EOpenSSLError.Create('Password needed');

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
begin
  BuffStart := 0;
  SetLength(Salt, 0);

  if Assigned(FCipherProc) then
    cipher := FCipherProc()
  else
    cipher := EVP_aes_256_cbc();

  if FPassphrase.FType = ptPassword then
  begin
    salt := EVP_GetSalt;
    EVP_GetKeyIV(FPassphrase.FValue, cipher, salt, key, InitVector);
  end
  else if FPassphrase.FType = ptKeys then
  begin
    Key := FPassphrase.FKey;
    InitVector := FPassphrase.FInitVector;
  end
  else
    raise EOpenSSLError.Create('Password needed');

  SetLength(InputBuffer, InputStream.Size);
  InputStream.ReadBuffer(InputBuffer[0], InputStream.Size);

  Context := EVP_CIPHER_CTX_new();
  if Context = nil then
    RaiseOpenSSLError('Cannot initialize context');

  try
    if EVP_EncryptInit_ex(Context, cipher, nil, @Key[0], @InitVector[0]) <> 1 then
      RaiseOpenSSLError('Cannot initialize encryption process');

    BlockSize := EVP_CIPHER_CTX_block_size(Context);
    if Length(salt) > 0 then
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

class procedure TEncUtil.RegisterCipher(const Name: TCipherName;
  Proc: TCipherProc);
var
  Value :TCipherInfo;
begin
  Value.Name := Name;
  Value.Proc := Proc;
  FCipherList.Add(Value);
end;

class procedure TEncUtil.RegisterDefaultCiphers;
begin
  CheckOpenSSLLibrary;
  if FCipherList.Count = 0 then
  begin

  // AES
  RegisterCipher('AES', EVP_aes_256_cbc);
  RegisterCipher('AES-128', EVP_aes_128_cbc);
  RegisterCipher('AES-192', EVP_aes_192_cbc);
  RegisterCipher('AES-256', EVP_aes_256_cbc);

  RegisterCipher('AES-CBC', EVP_aes_256_cbc);
  RegisterCipher('AES-128-CBC', EVP_aes_128_cbc);
  RegisterCipher('AES-192-CBC', EVP_aes_192_cbc);
  RegisterCipher('AES-256-CBC', EVP_aes_256_cbc);

  RegisterCipher('AES-CFB', EVP_aes_256_cfb128);
  RegisterCipher('AES-128-CFB', EVP_aes_128_cfb128);
  RegisterCipher('AES-192-CFB', EVP_aes_192_cfb128);
  RegisterCipher('AES-256-CFB', EVP_aes_256_cfb128);

  RegisterCipher('AES-CFB1', EVP_aes_256_cfb1);
  RegisterCipher('AES-128-CFB1', EVP_aes_128_cfb1);
  RegisterCipher('AES-192-CFB1', EVP_aes_192_cfb1);
  RegisterCipher('AES-256-CFB1', EVP_aes_256_cfb1);

  RegisterCipher('AES-CFB8', EVP_aes_256_cfb8);
  RegisterCipher('AES-128-CFB8', EVP_aes_128_cfb8);
  RegisterCipher('AES-192-CFB8', EVP_aes_192_cfb8);
  RegisterCipher('AES-256-CFB8', EVP_aes_256_cfb8);

  RegisterCipher('AES-ECB', EVP_aes_256_ecb);
  RegisterCipher('AES-128-ECB', EVP_aes_128_ecb);
  RegisterCipher('AES-192-ECB', EVP_aes_192_ecb);
  RegisterCipher('AES-256-ECB', EVP_aes_256_ecb);

  RegisterCipher('AES-OFB', EVP_aes_256_ofb);
  RegisterCipher('AES-128-OFB', EVP_aes_128_ofb);
  RegisterCipher('AES-192-OFB', EVP_aes_192_ofb);
  RegisterCipher('AES-256-OFB', EVP_aes_256_ofb);

  // Blowfish
  RegisterCipher('BF', EVP_bf_cbc);
  RegisterCipher('BF-CBC', EVP_bf_cbc);
  RegisterCipher('BF-ECB', EVP_bf_ecb);
  RegisterCipher('BF-CBF', EVP_bf_cfb64);
  RegisterCipher('BF-OFB', EVP_bf_ofb);

  // DES
  RegisterCipher('DES-CBC', EVP_des_cbc);
  RegisterCipher('DES', EVP_des_cbc);
  RegisterCipher('DES-CFB', EVP_des_cfb64);
  RegisterCipher('DES-OFB', EVP_des_ofb);
  RegisterCipher('DES-ECB', EVP_des_ecb);

  // Two key triple DES EDE
  RegisterCipher('DES-EDE-CBC', EVP_des_ede_cbc);
  RegisterCipher('DES-EDE', EVP_des_ede);
  RegisterCipher('DES-EDE-CFB', EVP_des_ede_cfb64);
  RegisterCipher('DES-EDE-OFB', EVP_des_ede_ofb);

  // Two key triple DES EDE
  RegisterCipher('DES-EDE3-CBC', EVP_des_ede3_cbc);
  RegisterCipher('DES-EDE3', EVP_des_ede3);
  RegisterCipher('DES3', EVP_des_ede3);
  RegisterCipher('DES-EDE3-CFB', EVP_des_ede3_cfb64);
  RegisterCipher('DES-EDE3-OFB', EVP_des_ede3_ofb);

  // DESX algorithm
  RegisterCipher('DESX', EVP_desx_cbc);

  // IDEA algorithm
  RegisterCipher('IDEA-CBC', EVP_idea_cbc);
  RegisterCipher('IDEA', EVP_idea_cbc);
  RegisterCipher('IDEA-CFB', EVP_idea_cfb64);
  RegisterCipher('IDEA-ECB', EVP_idea_ecb);
  RegisterCipher('IDEA-OFB', EVP_idea_ofb);

  // RC2
  RegisterCipher('RC2-CBC', EVP_rc2_cbc);
  RegisterCipher('RC2', EVP_rc2_cbc);
  RegisterCipher('RC2-CFB', EVP_rc2_cfb64);
  RegisterCipher('RC2-ECB', EVP_rc2_ecb);
  RegisterCipher('RC2-OFB', EVP_rc2_ofb);
  RegisterCipher('RC2-64-CBC', nil);
  RegisterCipher('RC2-40-CBC', nil);

  // RC4
  RegisterCipher('RC4', EVP_rc4);
  RegisterCipher('RC4-40', EVP_rc4_40);

  end;
end;

procedure TEncUtil.SetCipher(const Value: TCipherName);
begin
  FCipherProc := FCipherList.GetProc(Value);
  if @FCipherProc = nil then
    raise EOpenSSLError.CreateFmt('Cipher not found: "%s"', [Value]);
  FCipher := Value;
end;

class procedure TEncUtil.SupportedCiphers(Ciphers: TStrings);
var
  CipherInfo :TCipherInfo;
  LocalCipherList :TList<TCipherInfo>;
begin
  RegisterDefaultCiphers;
  Ciphers.Clear;
  LocalCipherList := FCipherList.LockList;
  try
    for CipherInfo in LocalCipherList do
      Ciphers.Add(CipherInfo.Name);
  finally
    FCipherList.UnlockList;
  end;
end;

class constructor TEncUtil.Create;
begin
  FCipherList := TCipherList.Create;
end;

constructor TEncUtil.Create;
begin
  inherited Create;
  TEncUtil.RegisterDefaultCiphers;
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

class destructor TEncUtil.Destroy;
begin
  FCipherList.Free;
end;

{ TCipherList }

function TCipherList.Count: Integer;
var
  LocalCipherList :TList<TCipherInfo>;
begin
  LocalCipherList := LockList;
  try
    Result := LocalCipherList.Count;
  finally
    UnlockList;
  end;
end;

function TCipherList.GetProc(const Name: TCipherName): TCipherProc;
var
  CipherInfo :TCipherInfo;
  LocalCipherList :TList<TCipherInfo>;
begin
  Result := nil;
  LocalCipherList := LockList;
  try
    for CipherInfo in LocalCipherList do
      if CipherInfo.Name = Name then
      begin
        Result := CipherInfo.Proc;
        Break;
      end;
  finally
    UnlockList;
  end;
end;

{ TPassphrase }

constructor TPassphrase.Create(const Key, InitVector: TBytes);
begin
  FType := ptKeys;
  FKey := Key;
  FInitVector := InitVector;
end;

constructor TPassphrase.Create(const Password: string; Encoding: TEncoding);
begin
  FType := ptPassword;
  FValue := Encoding.GetBytes(Password);
end;

class operator TPassphrase.Implicit(const Value: string): TPassphrase;
begin
  Result.FType := ptPassword;
  Result.FValue := TEncoding.UTF8.GetBytes(Value);
end;

class operator TPassphrase.Implicit(const Value: TBytes): TPassphrase;
begin
  Result.FType := ptPassword;
  Result.FValue := Value;
end;

end.
