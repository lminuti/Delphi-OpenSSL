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
unit SSLDemo.UnpackPKCS7Frame;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls;

type
  TUnpackPKCS7Frame = class(TFrame)
    lblPKCS7File: TLabel;
    edtInputFileName: TEdit;
    lblOutputFile: TLabel;
    edtOutputFileName: TEdit;
    btnUnpack: TButton;
    chkVerify: TCheckBox;
    chkNoVerify: TCheckBox;
    procedure btnUnpackClick(Sender: TObject);
  private
    { Private declarations }
  public
    constructor Create(AOwner: TComponent); override;
  end;

implementation

uses
  Winapi.ShellAPI,
  OpenSSL.SMIMEUtils;

{$R *.dfm}

procedure TUnpackPKCS7Frame.btnUnpackClick(Sender: TObject);
var
  SMIME: TSMIMEUtil;
  Verify: Integer;
  InputStream, OutputStream: TMemoryStream;
begin
  if not FileExists(edtInputFileName.Text) then
  begin
    ShowMessage(Format('File "%s" not found. You can create a test file using "create_p7m.bat"', [edtInputFileName.Text]));
    Exit;
  end;

  SMIME := TSMIMEUtil.Create;
  InputStream := TMemoryStream.Create;
  OutputStream := TMemoryStream.Create;
  try
    InputStream.LoadFromFile(edtInputFileName.Text);
    Verify := SMIME.Decrypt(InputStream, OutputStream, chkVerify.Checked, chkNoVerify.Checked);

    if chkVerify.Checked then
    begin
      if Verify = 1 then
        ShowMessage('Verification Successfull')
      else
        ShowMessage('Verification Failure')
    end;

    OutputStream.SaveToFile(edtOutputFileName.Text);
    ShellExecute(Handle, 'open', PChar(edtOutputFileName.Text), '', '', SW_SHOWDEFAULT);
  finally
    InputStream.Free;
    OutputStream.Free;
    SMIME.Free;
  end;
end;

constructor TUnpackPKCS7Frame.Create(AOwner: TComponent);
var
  TestFolder :string;
begin
  inherited;
  TestFolder := StringReplace(ExtractFilePath(ParamStr(0)), 'Samples\SSLDemo', 'TestData', [rfReplaceAll, rfIgnoreCase]);
  edtInputFileName.Text := TestFolder + 'TestPKCS7.pdf.p7m';
  edtOutputFileName.Text := TestFolder + 'TestPKCS7-out.pdf';
end;

end.
