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
unit SSLDemo.KeyPairFrame;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, OpenSSL.RSAUtils,
  Vcl.StdCtrls;

type
  TKeyPairFrame = class(TFrame)
    btnKeyPairGen: TButton;
    procedure btnKeyPairGenClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

implementation

{$R *.dfm}

procedure TKeyPairFrame.btnKeyPairGenClick(Sender: TObject);
var
  KeyPair: TRSAKeyPair;
  RSAUtil :TRSAUtil;
begin
  KeyPair := TRSAKeyPair.Create;
  try
    KeyPair.GenerateKey;

    RSAUtil := TRSAUtil.Create;
    try
      RSAUtil.PrivateKey := KeyPair.PrivateKey;
    finally
      RSAUtil.Free;
    end;

  finally
    KeyPair.Free;
  end;
end;

end.
