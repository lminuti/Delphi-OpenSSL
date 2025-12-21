object MainFrame: TMainFrame
  Left = 0
  Top = 0
  Width = 727
  Height = 605
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -15
  Font.Name = 'Segoe UI'
  Font.Style = []
  ParentFont = False
  TabOrder = 0
  DesignSize = (
    727
    605)
  object lblTextToCrypt: TLabel
    Left = 24
    Top = 345
    Width = 51
    Height = 20
    Caption = 'Test file'
  end
  object lblCertPath: TLabel
    Left = 24
    Top = 179
    Width = 68
    Height = 20
    Caption = 'Certificate'
  end
  object lblPriv: TLabel
    Left = 24
    Top = 214
    Width = 71
    Height = 20
    Caption = 'Private key'
  end
  object Label1: TLabel
    Left = 24
    Top = 248
    Width = 66
    Height = 20
    Caption = 'Public key'
  end
  object Label2: TLabel
    Left = 24
    Top = 16
    Width = 405
    Height = 19
    Caption = '1. Install OPENSSL and add it to your system path'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -16
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label3: TLabel
    Left = 24
    Top = 51
    Width = 469
    Height = 19
    Caption = '2. Generates the required keys and self-signed certificate'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -16
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label4: TLabel
    Left = 24
    Top = 142
    Width = 319
    Height = 19
    Caption = '4. Check the following files are created'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -16
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label5: TLabel
    Left = 24
    Top = 318
    Width = 179
    Height = 19
    Caption = '5. Generate a test file'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -16
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label6: TLabel
    Left = 24
    Top = 376
    Width = 289
    Height = 19
    Caption = '6. Try to encrypt with the cerificate'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -16
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label7: TLabel
    Left = 18
    Top = 511
    Width = 305
    Height = 19
    Caption = '8. Try to decrypt with the private key'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -16
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label8: TLabel
    Left = 18
    Top = 439
    Width = 295
    Height = 19
    Caption = '7. Try to encrypt with the public key'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -16
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label10: TLabel
    Left = 24
    Top = 282
    Width = 82
    Height = 20
    Caption = 'P7M test file'
  end
  object edtTextToCrypt: TEdit
    Left = 136
    Top = 342
    Width = 480
    Height = 28
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 4
  end
  object edtCertFile: TEdit
    Left = 136
    Top = 176
    Width = 480
    Height = 28
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 0
  end
  object btnCryptWithKey: TButton
    Left = 18
    Top = 464
    Width = 193
    Height = 33
    Caption = 'Public Crypt'
    TabOrder = 8
    OnClick = btnCryptWithKeyClick
  end
  object edtPriv: TEdit
    Left = 136
    Top = 211
    Width = 480
    Height = 28
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 1
  end
  object btnDecryptWithKey: TButton
    Left = 18
    Top = 536
    Width = 193
    Height = 32
    Caption = 'Private decrypt'
    TabOrder = 7
    OnClick = btnDecryptWithKeyClick
  end
  object edtPub: TEdit
    Left = 136
    Top = 245
    Width = 480
    Height = 28
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 2
  end
  object btnCryptWithCert: TButton
    Left = 24
    Top = 401
    Width = 193
    Height = 32
    Caption = 'Public Crypt with cert'
    TabOrder = 6
    OnClick = btnCryptWithCertClick
  end
  object btnGenerateSampleFile: TButton
    Left = 622
    Top = 340
    Width = 75
    Height = 30
    Anchors = [akTop, akRight]
    Caption = 'Generate'
    TabOrder = 5
    OnClick = btnGenerateSampleFileClick
  end
  object edtP7MTestFile: TEdit
    Left = 136
    Top = 279
    Width = 561
    Height = 28
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 3
  end
  object BtnGenerateCertificate: TButton
    Left = 24
    Top = 84
    Width = 215
    Height = 37
    Caption = 'Generate keys and certificate'
    TabOrder = 9
    OnClick = BtnGenerateCertificateClick
  end
  object BtnPrintCertificate: TButton
    Left = 622
    Top = 175
    Width = 75
    Height = 30
    Anchors = [akTop, akRight]
    Caption = 'Show'
    TabOrder = 10
    OnClick = BtnPrintCertificateClick
  end
  object BtnPrintPrivateKey: TButton
    Left = 622
    Top = 211
    Width = 75
    Height = 30
    Anchors = [akTop, akRight]
    Caption = 'Show'
    TabOrder = 11
    OnClick = BtnPrintPrivateKeyClick
  end
  object BtnPrintPublicKey: TButton
    Left = 622
    Top = 243
    Width = 75
    Height = 30
    Anchors = [akTop, akRight]
    Caption = 'Show'
    TabOrder = 12
    OnClick = BtnPrintPublicKeyClick
  end
end
