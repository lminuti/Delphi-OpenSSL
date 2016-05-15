unit SSLDemo.RSABufferFrame;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls;

type
  TRSABufferFrame = class(TFrame)
    memPub: TMemo;
    btnLoadPubKeyIntoMem: TButton;
    edtPub: TEdit;
    btnLoadPublicKey: TButton;
    grpPublicKey: TGroupBox;
    grpPrivateKey: TGroupBox;
    btnLoadPrivKeyIntoMemo: TButton;
    btnLoadPrivateKey: TButton;
    edtPriv: TEdit;
    memPriv: TMemo;
    grpCertificate: TGroupBox;
    btnLoadCertIntoMemo: TButton;
    btnLoadCert: TButton;
    edtCert: TEdit;
    memCert: TMemo;
    procedure btnLoadPubKeyIntoMemClick(Sender: TObject);
    procedure btnLoadPublicKeyClick(Sender: TObject);
    procedure btnLoadPrivKeyIntoMemoClick(Sender: TObject);
    procedure btnLoadCertIntoMemoClick(Sender: TObject);
    procedure btnLoadCertClick(Sender: TObject);
  private
    procedure PassphraseReader(Sender: TObject; var Passphrase: string);
    { Private declarations }
  public
    constructor Create(AOwner: TComponent); override;
  end;

implementation

uses
  OpenSSL.RSAUtils;

{$R *.dfm}

{ TRSABufferFrame }

procedure TRSABufferFrame.btnLoadCertClick(Sender: TObject);
var
  Buffer :TStream;
  Cerificate :TX509Cerificate;
begin
  Buffer := TStringStream.Create(memCert.Text);
  try
    Cerificate := TX509Cerificate.Create;
    try
      Cerificate.LoadFromStream(Buffer);
    finally
      Cerificate.Free;
    end;
  finally
    Buffer.Free;
  end;
end;

procedure TRSABufferFrame.btnLoadCertIntoMemoClick(Sender: TObject);
begin
  memCert.Lines.LoadFromFile(edtCert.Text);
end;

procedure TRSABufferFrame.btnLoadPrivKeyIntoMemoClick(Sender: TObject);
begin
  memPriv.Lines.LoadFromFile(edtPriv.Text);
end;

procedure TRSABufferFrame.btnLoadPubKeyIntoMemClick(Sender: TObject);
begin
  memPub.Lines.LoadFromFile(edtPub.Text);
end;

procedure TRSABufferFrame.btnLoadPublicKeyClick(Sender: TObject);
var
  Buffer :TStream;
  PrivateKey :TRSAPrivateKey;
begin
  Buffer := TStringStream.Create(memPriv.Text);
  try
    PrivateKey := TRSAPrivateKey.Create;
    try
      PrivateKey.OnNeedPassphrase := PassphraseReader;
      PrivateKey.LoadFromStream(Buffer);
    finally
      PrivateKey.Free;
    end;
  finally
    Buffer.Free;
  end;
end;

constructor TRSABufferFrame.Create(AOwner: TComponent);
var
  TestFolder :string;
begin
  inherited;
  TestFolder := StringReplace(ExtractFilePath(ParamStr(0)), 'Samples\SSLDemo', 'TestData', [rfReplaceAll, rfIgnoreCase]);

  edtCert.Text := TestFolder + 'publiccert.pem';
  edtPriv.Text := TestFolder + 'privatekey.pem';
  edtPub.Text := TestFolder + 'publickey.pem';
end;

procedure TRSABufferFrame.PassphraseReader(Sender: TObject; var Passphrase: string);
begin
  Passphrase := InputBox(Name, 'Passphrase', '');
end;

end.
