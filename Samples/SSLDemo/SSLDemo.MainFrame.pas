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
unit SSLDemo.MainFrame;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.StdCtrls, Vcl.Controls, Vcl.Forms, Vcl.Dialogs;

type
  TMainFrame = class(TFrame)
    edtTextToCrypt: TEdit;
    lblTextToCrypt: TLabel;
    lblCertPath: TLabel;
    edtCertFile: TEdit;
    btnCryptWithKey: TButton;
    lblPriv: TLabel;
    edtPriv: TEdit;
    btnDecryptWithKey: TButton;
    Label1: TLabel;
    edtPub: TEdit;
    btnCryptWithCert: TButton;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    btnGenerateSampleFile: TButton;
    Label6: TLabel;
    Label7: TLabel;
    Label8: TLabel;
    Label9: TLabel;
    Label10: TLabel;
    edtP7MTestFile: TEdit;
    Label11: TLabel;
    BtnGenerateKeyPairs: TButton;
    procedure btnCryptWithKeyClick(Sender: TObject);
    procedure btnDecryptWithKeyClick(Sender: TObject);
    procedure btnCryptWithCertClick(Sender: TObject);
    procedure btnGenerateSampleFileClick(Sender: TObject);
    procedure BtnGenerateKeyPairsClick(Sender: TObject);
  private
    procedure PassphraseReader(Sender :TObject; var Passphrase :string);
  public
    constructor Create(AOwner: TComponent); override;
  end;

implementation

{$R *.dfm}

uses
  OpenSSL.RSAUtils, System.IOUtils, IdSSLOpenSSLHeaders;

{ TMainForm }

procedure TMainFrame.btnCryptWithKeyClick(Sender: TObject);
var
  RSAUtil :TRSAUtil;
begin
  RSAUtil := TRSAUtil.Create;
  try
    RSAUtil.PublicKey.LoadFromFile(edtPub.Text);
    RSAUtil.PublicEncrypt(edtTextToCrypt.Text, edtTextToCrypt.Text + '.keycry');
  finally
    RSAUtil.Free;
  end;
end;

procedure TMainFrame.btnDecryptWithKeyClick(Sender: TObject);
var
  RSAUtil :TRSAUtil;
begin
  RSAUtil := TRSAUtil.Create;
  try
    RSAUtil.PrivateKey.OnNeedPassphrase := PassphraseReader;
    RSAUtil.PrivateKey.LoadFromFile(edtPriv.Text);
    RSAUtil.PrivateDecrypt(edtTextToCrypt.Text + '.keycry', edtTextToCrypt.Text + '.certdecry.txt');
  finally
    RSAUtil.Free;
  end;
end;

procedure TMainFrame.btnCryptWithCertClick(Sender: TObject);
var
  RSAUtil :TRSAUtil;
  Cerificate :TX509Cerificate;
begin
  RSAUtil := TRSAUtil.Create;
  try
    Cerificate := TX509Cerificate.Create;
    try
      Cerificate.LoadFromFile(edtCertFile.Text);
      RSAUtil.PublicKey.LoadFromCertificate(Cerificate);
      RSAUtil.PublicEncrypt(edtTextToCrypt.Text, edtTextToCrypt.Text + '.certcry');
    finally
      Cerificate.Free;
    end;
  finally
    RSAUtil.Free;
  end;
end;

procedure TMainFrame.btnGenerateSampleFileClick(Sender: TObject);
var
  SL :TStringList;
begin
  SL := TStringList.Create;
  try
    SL.Text := 'Hello, world!   السلام عليكم';
    SL.SaveToFile(edtTextToCrypt.Text, TEncoding.Unicode);
  finally
    SL.Free;
  end;
end;

constructor TMainFrame.Create(AOwner: TComponent);
var
  TestFolder :string;
begin
  inherited;
  TestFolder := StringReplace(ExtractFilePath(ParamStr(0)), 'Samples\SSLDemo', 'TestData', [rfReplaceAll, rfIgnoreCase]);

  edtCertFile.Text := TestFolder + 'publiccert.pem';
  edtPriv.Text := TestFolder + 'privatekey.pem';
  edtPub.Text := TestFolder + 'publickey.pem';
  edtTextToCrypt.Text := TestFolder + 'test.txt';
  edtP7MTestFile.Text := TestFolder + 'TestPKCS7.pdf.p7m';
end;

procedure TMainFrame.PassphraseReader(Sender: TObject; var Passphrase: string);
begin
  Passphrase := InputBox(Name, 'Passphrase', '');
end;

procedure TMainFrame.BtnGenerateKeyPairsClick(Sender: TObject);
var
  FPublicKey, FPrivateKey: TBytes;
begin

  if CreateRSAKeyPairs_PKCS(FPublicKey, FPrivateKey) then
  begin
    System.IOUtils.TFile.WriteAllBytes(edtPriv.Text, FPrivateKey);
    System.IOUtils.TFile.WriteAllBytes(edtPub.Text, FPublicKey);
  end
  else
  begin
    ShowMessage('Unable to generate RSA keys');
  end;

end;




end.
