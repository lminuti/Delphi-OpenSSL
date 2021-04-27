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
    edtCertFileName: TEdit;
    lblCertFile: TLabel;
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
  InputStream, OutputStream: TMemoryStream;
begin
  SMIME := TSMIMEUtil.Create;
  InputStream := TMemoryStream.Create;
  OutputStream := TMemoryStream.Create;
  try
    InputStream.LoadFromFile(edtInputFileName.Text);
    if not SMIME.Decrypt(InputStream, OutputStream, AnsiString(edtCertFileName.Text), chkVerify.Checked, chkNoVerify.Checked) then
    begin
      if chkVerify.Checked
        then ShowMessage('Verification Failure')
        else ShowMessage('Extraction Failure');
      Exit;
    end;

    OutputStream.SaveToFile(edtOutputFileName.Text);

    if chkVerify.Checked
      then ShowMessage('Verification Successfull')
      else ShowMessage('Extraction Successfull');

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
  edtCertFileName.Text := TestFolder + 'TestPKCS7-cert.pem';
end;

end.
