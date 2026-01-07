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
unit SSLDemo.SignFrame;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls;

type
  TSignFrame = class(TFrame)
    btnSign: TButton;
    memTest: TMemo;
    btnVerify: TButton;
    Label1: TLabel;
    Label2: TLabel;
    edtInputFileName: TEdit;
    edtOutputFileName: TEdit;
    BtnGenrateFile: TButton;
    procedure btnSignClick(Sender: TObject);
    procedure btnVerifyClick(Sender: TObject);
    procedure BtnGenrateFileClick(Sender: TObject);
  private
    FTestFolder :string;
  public
    constructor Create(AOwner: TComponent); override;
  end;

implementation

{$R *.dfm}

uses
  OpenSSL.RSAUtils;

procedure TSignFrame.btnSignClick(Sender: TObject);
var
  RSAUtil: TRSAUtil;
begin
  RSAUtil := TRSAUtil.Create;
  try
    RSAUtil.PrivateKey.LoadFromFile(FTestFolder + 'privatekey.pem');
    RSAUtil.PublicKey.LoadFromFile(FTestFolder + 'publickey.pem');
    RSAUtil.Sign(edtInputFileName.Text, edtOutputFileName.Text);
  finally
    RSAUtil.Free;
  end;
end;

procedure TSignFrame.BtnGenrateFileClick(Sender: TObject);
begin
  memTest.Lines.SaveToFile(edtInputFileName.Text);
end;

constructor TSignFrame.Create(AOwner: TComponent);
begin
  inherited;
  FTestFolder := StringReplace(ExtractFilePath(ParamStr(0)), 'Samples\SSLDemo', 'TestData', [rfReplaceAll, rfIgnoreCase]);

  edtInputFileName.Text := FTestFolder + 'SIGN_TEST.txt';
  edtOutputFileName.Text := FTestFolder + 'SIGN_TEST_SIGNED.txt';
end;

procedure TSignFrame.btnVerifyClick(Sender: TObject);
var
  RSAUtil: TRSAUtil;
begin
  RSAUtil := TRSAUtil.Create;
  try
    RSAUtil.PrivateKey.LoadFromFile(FTestFolder + 'privatekey.pem');
    RSAUtil.PublicKey.LoadFromFile(FTestFolder + 'publickey.pem');
    if RSAUtil.Verify(edtInputFileName.Text, edtOutputFileName.Text) then
      ShowMessage('Signature OK')
    else
      ShowMessage('Signature error!')
  finally
    RSAUtil.Free;
  end;
end;

end.
