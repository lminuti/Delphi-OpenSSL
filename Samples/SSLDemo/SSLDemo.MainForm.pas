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
    tabTutorial: TTabSheet;
    tabRSABuffer: TTabSheet;
    tabEncryption: TTabSheet;
    tabUnpackPKCS7: TTabSheet;
    TabRandom: TTabSheet;
    procedure FormCreate(Sender: TObject);
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
  SSLDemo.MainFrame, SSLDemo.RSABufferFrame, SSLDemo.EncFrame, SSLDemo.UnpackPKCS7Frame,
  SSLDemo.RandFrame;

{ TMainForm }

procedure TMainForm.FormCreate(Sender: TObject);
var
  MainFrame: TMainFrame;
  RSABufferFrame :TRSABufferFrame;
  EncFrame :TEncFrame;
  UnpackFrame: TUnpackPKCS7Frame;
  RandomFrame: TRandomFrame;
begin
  pgcMain.ActivePageIndex := 0;

  MainFrame := TMainFrame.Create(Application);
  MainFrame.Parent := tabTutorial;

  RSABufferFrame := TRSABufferFrame.Create(Application);
  RSABufferFrame.Parent := tabRSABuffer;

  EncFrame := TEncFrame.Create(Application);
  EncFrame.Parent := tabEncryption;

  UnpackFrame := TUnpackPKCS7Frame.Create(Application);
  UnpackFrame.Parent := tabUnpackPKCS7;
  
  RandomFrame := TRandomFrame.Create(Application);
  RandomFrame.Parent := TabRandom;
end;

end.
