object MainFrame: TMainFrame
  Left = 0
  Top = 0
  Width = 591
  Height = 385
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  ParentFont = False
  TabOrder = 0
  object lblTextToCrypt: TLabel
    Left = 24
    Top = 195
    Width = 38
    Height = 13
    Caption = 'Test file'
  end
  object lblCertPath: TLabel
    Left = 24
    Top = 83
    Width = 50
    Height = 13
    Caption = 'Certificate'
  end
  object lblPriv: TLabel
    Left = 24
    Top = 110
    Width = 54
    Height = 13
    Caption = 'Private key'
  end
  object Label1: TLabel
    Left = 24
    Top = 137
    Width = 47
    Height = 13
    Caption = 'Public key'
  end
  object Label2: TLabel
    Left = 24
    Top = 16
    Width = 277
    Height = 13
    Caption = '1. Install OPENSSL and add it to your system path'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label3: TLabel
    Left = 24
    Top = 35
    Width = 291
    Height = 13
    Caption = '2. Go to the testdata folder and run create_cert.bat'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label4: TLabel
    Left = 24
    Top = 54
    Width = 217
    Height = 13
    Caption = '3. Check the following files are created'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label5: TLabel
    Left = 24
    Top = 168
    Width = 122
    Height = 13
    Caption = '4. Generate a test file'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label6: TLabel
    Left = 24
    Top = 224
    Width = 199
    Height = 13
    Caption = '5. Try to encrypt with the cerificate'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label7: TLabel
    Left = 24
    Top = 274
    Width = 211
    Height = 13
    Caption = '6. Try to decrypt with the private key'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label8: TLabel
    Left = 24
    Top = 324
    Width = 203
    Height = 13
    Caption = '5. Try to encrypt with the public key'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object edtTextToCrypt: TEdit
    Left = 136
    Top = 192
    Width = 353
    Height = 21
    TabOrder = 0
  end
  object edtCertFile: TEdit
    Left = 136
    Top = 80
    Width = 435
    Height = 21
    TabOrder = 1
  end
  object btnCryptWithKey: TButton
    Left = 24
    Top = 344
    Width = 131
    Height = 25
    Caption = 'Public Crypt'
    TabOrder = 2
    OnClick = btnCryptWithKeyClick
  end
  object edtPriv: TEdit
    Left = 136
    Top = 107
    Width = 435
    Height = 21
    TabOrder = 3
  end
  object btnDecryptWithKey: TButton
    Left = 24
    Top = 293
    Width = 131
    Height = 25
    Caption = 'Private decrypt'
    TabOrder = 4
    OnClick = btnDecryptWithKeyClick
  end
  object edtPub: TEdit
    Left = 136
    Top = 134
    Width = 435
    Height = 21
    TabOrder = 5
  end
  object btnCryptWithCert: TButton
    Left = 24
    Top = 243
    Width = 131
    Height = 25
    Caption = 'Public Crypt with cert'
    TabOrder = 6
    OnClick = btnCryptWithCertClick
  end
  object btnGenerateSampleFile: TButton
    Left = 495
    Top = 190
    Width = 75
    Height = 25
    Caption = 'Generate'
    TabOrder = 7
    OnClick = btnGenerateSampleFileClick
  end
end
