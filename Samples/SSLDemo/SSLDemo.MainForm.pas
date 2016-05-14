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
unit SSLDemo.MainForm;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.Mask,
  JvExMask, JvToolEdit;

type
  TMainForm = class(TForm)
    edtTextToCrypt: TEdit;
    lblTextToCrypt: TLabel;
    lblCertPath: TLabel;
    edtCertFile: TEdit;
    Button1: TButton;
    lblPriv: TLabel;
    edtPriv: TEdit;
    Button2: TButton;
    Label1: TLabel;
    edtPub: TEdit;
    Button3: TButton;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    Button4: TButton;
    Label6: TLabel;
    Label7: TLabel;
    Label8: TLabel;
    procedure FormCreate(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure Button4Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  MainForm: TMainForm;

implementation

{$R *.dfm}

uses
  OpenSSL.RSAUtils;

{ TMainForm }

procedure TMainForm.Button1Click(Sender: TObject);
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

procedure TMainForm.Button2Click(Sender: TObject);
var
  RSAUtil :TRSAUtil;
begin
  RSAUtil := TRSAUtil.Create;
  try
    RSAUtil.PrivateKey.LoadFromFile(edtPriv.Text);
    RSAUtil.PrivateDecrypt(edtTextToCrypt.Text + '.certcry', edtTextToCrypt.Text + '.certdecry.txt');
  finally
    RSAUtil.Free;
  end;
end;

procedure TMainForm.Button3Click(Sender: TObject);
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

procedure TMainForm.Button4Click(Sender: TObject);
var
  SL :TStringList;
begin
  SL := TStringList.Create;
  try
    SL.Text := 'Hello, world!';
    SL.SaveToFile(edtTextToCrypt.Text);
  finally
    SL.Free;
  end;
end;

procedure TMainForm.FormCreate(Sender: TObject);
var
  TestFolder :string;
begin
  TestFolder := StringReplace(ExtractFilePath(ParamStr(0)), 'Samples\SSLDemo', 'TestData', [rfReplaceAll, rfIgnoreCase]);

  edtCertFile.Text := TestFolder + 'publiccert.pem';
  edtPriv.Text := TestFolder + 'privatekey.pem';
  edtPub.Text := TestFolder + 'publickey.pem';
  edtTextToCrypt.Text := TestFolder + 'test.txt';
end;

end.
