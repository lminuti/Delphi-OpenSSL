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
