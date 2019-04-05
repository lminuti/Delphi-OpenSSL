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
  System.Classes, Vcl.StdCtrls, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.ComCtrls;

type
  TMainForm = class(TForm)
    pgcMain: TPageControl;
    procedure FormCreate(Sender: TObject);
  private
    procedure AddFrame(const Caption: string; FrameClass: TControlClass);
  public
    { Public declarations }
  end;

var
  MainForm: TMainForm;

implementation

{$R *.dfm}

uses
  SSLDemo.MainFrame, SSLDemo.RSABufferFrame, SSLDemo.EncFrame, SSLDemo.UnpackPKCS7Frame,
  SSLDemo.RandFrame, SSLDemo.KeyPairFrame;

{ TMainForm }

procedure TMainForm.AddFrame(const Caption: string;
  FrameClass: TControlClass);
var
  TabSheet: TTabSheet;
  AFrame: TControl;
begin
  TabSheet := TTabSheet.Create(pgcMain);
  TabSheet.Caption := Caption;
  TabSheet.PageControl := pgcMain;

  AFrame := FrameClass.Create(Application);
  AFrame.Parent := TabSheet;
end;

procedure TMainForm.FormCreate(Sender: TObject);
begin
  AddFrame('Tutorial', TMainFrame);
  AddFrame('RSABuffer', TRSABufferFrame);
  AddFrame('Encryption', TEncFrame);
  AddFrame('Random', TRandomFrame);
  AddFrame('Unpack PKCS7', TUnpackPKCS7Frame);
  AddFrame('KeyPair', TKeyPairFrame);
end;

end.
