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
