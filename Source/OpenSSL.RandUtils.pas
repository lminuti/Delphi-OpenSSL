{******************************************************************************}
{                                                                              }
{  Delphi OPENSSL Library                                                      }
{  Copyright (c) 2018 Luca Minuti                                              }
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
unit OpenSSL.RandUtils;

// https://www.openssl.org/docs/man1.1.0/crypto/RAND_load_file.html
// https://www.openssl.org/docs/man1.1.1/man3/RAND_poll.html
// https://www.openssl.org/docs/man1.1.0/crypto/RAND_bytes.html

interface

uses
  System.SysUtils;

type
  TRandUtil = class(TObject)
  public
    // Calling InitPool is not necessary, because the DRBG polls the entropy source automatically
    class procedure InitPool;
    // true if the CSPRNG has been seeded with enough data
    class function Initialized: Boolean;
    // reads a number of bytes from file filename and adds them to the PRNG
    // if max_bytes is -1, the complete file is read
    // returns the number of bytes read
    class function LoadSeedFromFile(const FileName: string; MaxBytes: Integer = -1): Integer;
    // writes a number of random bytes (currently 1024) to file filename
    // which can be used to initialize the PRNG by calling RAND_load_file() in a later session
    // returns the number of bytes written
    class function SaveSeedToFile(const FileName: string): Integer;
    // generates a default path for the random seed file
    class function GetDefaultSeedFileName: string;
    // Generate a random number
    class function GetRandomBytes(const Size: Integer): TBytes;
    // Generate a cryptographically secure random number
    class function GetPseudoRandomBytes(const Size: Integer): TBytes;
  end;

implementation

uses
  OpenSSL.libeay32, OpenSSL.Core;

{ TRandUtil }

class function TRandUtil.GetDefaultSeedFileName: string;
const
  MaxLen = 255;
var
  Filename: AnsiString;
  FilenameP: PAnsiChar;
begin
  SetLength(Filename, MaxLen);
  FilenameP := RAND_file_name(@Filename[1], MaxLen);
  if not Assigned(FilenameP) then
    RaiseOpenSSLError('RAND_file_name error');
  Result := string(AnsiString(PAnsiChar(Filename)));
end;

class function TRandUtil.GetPseudoRandomBytes(const Size: Integer): TBytes;
var
  ErrCode: Integer;
begin
  SetLength(Result, Size);
  ErrCode := RAND_pseudo_bytes(@Result[0], Size);
  if ErrCode = -1 then
    RaiseOpenSSLError('RAND method not supported');
  if ErrCode = 0 then
    RaiseOpenSSLError('RAND_pseudo_bytes error');
end;

class function TRandUtil.GetRandomBytes(const Size: Integer): TBytes;
var
  ErrCode: Integer;
begin
  SetLength(Result, Size);
  ErrCode := RAND_bytes(@Result[0], Size);
  if ErrCode = -1 then
    RaiseOpenSSLError('RAND method not supported');
  if ErrCode = 0 then
    RaiseOpenSSLError('RAND_bytes error');
end;

class function TRandUtil.Initialized: Boolean;
var
  ErrCode: Integer;
begin
  ErrCode := RAND_status();
  Result := ErrCode = 1;
end;

class procedure TRandUtil.InitPool;
var
  ErrCode: Integer;
begin
  ErrCode := RAND_poll();
  if ErrCode <> 1 then
    RaiseOpenSSLError('RAND_poll error');
end;

class function TRandUtil.LoadSeedFromFile(const FileName: string;
  MaxBytes: Integer): Integer;
begin
  Result := RAND_load_file(@FileName[1], MaxBytes);
  if Result < 0 then
    RaiseOpenSSLError('RAND_load_file error');
end;

class function TRandUtil.SaveSeedToFile(const FileName: string): Integer;
begin
  Result := RAND_write_file(@FileName[1]);
  if Result < 0 then
    RaiseOpenSSLError('RAND_write_file error');
end;

end.
