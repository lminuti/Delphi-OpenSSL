object MainFrame: TMainFrame
  Left = 0
  Top = 0
  Width = 591
  Height = 559
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  ParentFont = False
  TabOrder = 0
  object lblTextToCrypt: TLabel
    Left = 24
    Top = 227
    Width = 38
    Height = 13
    Caption = 'Test file'
  end
  object lblCertPath: TLabel
    Left = 24
    Top = 99
    Width = 50
    Height = 13
    Caption = 'Certificate'
  end
  object lblPriv: TLabel
    Left = 24
    Top = 126
    Width = 54
    Height = 13
    Caption = 'Private key'
  end
  object Label1: TLabel
    Left = 24
    Top = 153
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
    Top = 70
    Width = 217
    Height = 13
    Caption = '4. Check the following files are created'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label5: TLabel
    Left = 24
    Top = 200
    Width = 122
    Height = 13
    Caption = '5. Generate a test file'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label6: TLabel
    Left = 24
    Top = 256
    Width = 199
    Height = 13
    Caption = '6. Try to encrypt with the cerificate'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label7: TLabel
    Left = 24
    Top = 306
    Width = 211
    Height = 13
    Caption = '7. Try to decrypt with the private key'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label8: TLabel
    Left = 24
    Top = 356
    Width = 203
    Height = 13
    Caption = '8. Try to encrypt with the public key'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label9: TLabel
    Left = 24
    Top = 51
    Width = 351
    Height = 13
    Caption = '3. Run create_p7m.bat or Click generate KeyPairs for rsa 2048'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label10: TLabel
    Left = 24
    Top = 180
    Width = 59
    Height = 13
    Caption = 'P7M test file'
  end
  object Label11: TLabel
    Left = 22
    Top = 412
    Width = 114
    Height = 13
    Caption = '9. Genrate Key Pairs'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object edtTextToCrypt: TEdit
    Left = 136
    Top = 224
    Width = 353
    Height = 21
    TabOrder = 4
  end
  object edtCertFile: TEdit
    Left = 136
    Top = 96
    Width = 435
    Height = 21
    TabOrder = 0
  end
  object btnCryptWithKey: TButton
    Left = 24
    Top = 376
    Width = 131
    Height = 25
    Caption = 'Public Crypt'
    TabOrder = 8
    OnClick = btnCryptWithKeyClick
  end
  object edtPriv: TEdit
    Left = 136
    Top = 123
    Width = 435
    Height = 21
    TabOrder = 1
  end
  object btnDecryptWithKey: TButton
    Left = 24
    Top = 325
    Width = 131
    Height = 25
    Caption = 'Private decrypt'
    TabOrder = 7
    OnClick = btnDecryptWithKeyClick
  end
  object edtPub: TEdit
    Left = 136
    Top = 150
    Width = 435
    Height = 21
    TabOrder = 2
  end
  object btnCryptWithCert: TButton
    Left = 24
    Top = 275
    Width = 131
    Height = 25
    Caption = 'Public Crypt with cert'
    TabOrder = 6
    OnClick = btnCryptWithCertClick
  end
  object btnGenerateSampleFile: TButton
    Left = 495
    Top = 222
    Width = 75
    Height = 25
    Caption = 'Generate'
    TabOrder = 5
    OnClick = btnGenerateSampleFileClick
  end
  object edtP7MTestFile: TEdit
    Left = 136
    Top = 177
    Width = 435
    Height = 21
    TabOrder = 3
  end
  object BtnGenerateKeyPairs: TButton
    Left = 22
    Top = 431
    Width = 131
    Height = 25
    Caption = 'Generate KeyPairs'
    TabOrder = 9
    OnClick = BtnGenerateKeyPairsClick
  end
end
