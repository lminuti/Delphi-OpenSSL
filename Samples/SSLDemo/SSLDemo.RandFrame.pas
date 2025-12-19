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
unit SSLDemo.RandFrame;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, System.NetEncoding,
  System.IOUtils;

type
  TRandomFrame = class(TFrame)
    EditSize: TEdit;
    EditResult: TEdit;
    ButtonRandom: TButton;
    LabelSize: TLabel;
    procedure ButtonRandomClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

implementation

uses
  OpenSSL.RandUtils;

{$R *.dfm}

procedure TRandomFrame.ButtonRandomClick(Sender: TObject);
var
  Buffer: TBytes;
begin
  Buffer := TRandUtil.GetRandomBytes(StrToInt(EditSize.Text));
  EditResult.Text := TNetEncoding.Base64.EncodeBytesToString(Buffer);
end;

end.
