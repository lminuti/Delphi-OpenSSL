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
program SSLDemo;

uses
  Vcl.Forms,
  SSLDemo.MainForm in 'SSLDemo.MainForm.pas' {MainForm},
  SSLDemo.MainFrame in 'SSLDemo.MainFrame.pas' {MainFrame: TFrame},
  SSLDemo.RSABufferFrame in 'SSLDemo.RSABufferFrame.pas' {RSABufferFrame: TFrame},
  SSLDemo.EncFrame in 'SSLDemo.EncFrame.pas' {EncFrame: TFrame},
  OpenSSL.Core in '..\..\Source\OpenSSL.Core.pas',
  OpenSSL.EncUtils in '..\..\Source\OpenSSL.EncUtils.pas',
  OpenSSL.libeay32 in '..\..\Source\OpenSSL.libeay32.pas',
  OpenSSL.RSAUtils in '..\..\Source\OpenSSL.RSAUtils.pas',
  OpenSSL.SMIMEUtils in '..\..\Source\OpenSSL.SMIMEUtils.pas',
  SSLDemo.RandFrame in 'SSLDemo.RandFrame.pas' {RandomFrame: TFrame},
  SSLDemo.UnpackPKCS7Frame in 'SSLDemo.UnpackPKCS7Frame.pas' {UnpackPKCS7Frame: TFrame},
  OpenSSL.RandUtils in '..\..\Source\OpenSSL.RandUtils.pas',
  SSLDemo.KeyPairFrame in 'SSLDemo.KeyPairFrame.pas' {KeyPairFrame: TFrame},
  OpenSSL.CMSHeaders in '..\..\Source\OpenSSL.CMSHeaders.pas';

{$R *.res}

begin
  ReportMemoryLeaksOnShutdown := True;
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
