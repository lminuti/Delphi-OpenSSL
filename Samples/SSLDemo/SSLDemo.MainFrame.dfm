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
    Top = 275
    Width = 38
    Height = 13
    Caption = 'Test file'
  end
  object lblCertPath: TLabel
    Left = 24
    Top = 147
    Width = 50
    Height = 13
    Caption = 'Certificate'
  end
  object lblPriv: TLabel
    Left = 24
    Top = 174
    Width = 54
    Height = 13
    Caption = 'Private key'
  end
  object Label1: TLabel
    Left = 24
    Top = 201
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
    Left = 60
    Top = 35
    Width = 215
    Height = 13
    Caption = '2. Choose one of the following options:'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label4: TLabel
    Left = 24
    Top = 118
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
    Top = 248
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
    Top = 304
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
    Top = 354
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
    Top = 404
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
    Top = 99
    Width = 129
    Height = 13
    Caption = '3. Run create_p7m.bat'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label10: TLabel
    Left = 24
    Top = 228
    Width = 59
    Height = 13
    Caption = 'P7M test file'
  end
  object Label11: TLabel
    Left = 22
    Top = 460
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
  object Label12: TLabel
    Left = 72
    Top = 54
    Width = 298
    Height = 13
    Caption = '2a. Go to the testdata folder and run create_cert.bat'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object Label13: TLabel
    Left = 72
    Top = 73
    Width = 417
    Height = 13
    Caption = 
      '2b. Press the "Generate KeyPairs" button (it doen'#39't create the c' +
      'ertificate)'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object edtTextToCrypt: TEdit
    Left = 136
    Top = 272
    Width = 353
    Height = 21
    TabOrder = 4
  end
  object edtCertFile: TEdit
    Left = 136
    Top = 144
    Width = 435
    Height = 21
    TabOrder = 0
  end
  object btnCryptWithKey: TButton
    Left = 24
    Top = 424
    Width = 131
    Height = 25
    Caption = 'Public Crypt'
    TabOrder = 8
    OnClick = btnCryptWithKeyClick
  end
  object edtPriv: TEdit
    Left = 136
    Top = 171
    Width = 435
    Height = 21
    TabOrder = 1
  end
  object btnDecryptWithKey: TButton
    Left = 24
    Top = 373
    Width = 131
    Height = 25
    Caption = 'Private decrypt'
    TabOrder = 7
    OnClick = btnDecryptWithKeyClick
  end
  object edtPub: TEdit
    Left = 136
    Top = 198
    Width = 435
    Height = 21
    TabOrder = 2
  end
  object btnCryptWithCert: TButton
    Left = 24
    Top = 323
    Width = 131
    Height = 25
    Caption = 'Public Crypt with cert'
    TabOrder = 6
    OnClick = btnCryptWithCertClick
  end
  object btnGenerateSampleFile: TButton
    Left = 495
    Top = 270
    Width = 75
    Height = 25
    Caption = 'Generate'
    TabOrder = 5
    OnClick = btnGenerateSampleFileClick
  end
  object edtP7MTestFile: TEdit
    Left = 136
    Top = 225
    Width = 435
    Height = 21
    TabOrder = 3
  end
  object BtnGenerateKeyPairs: TButton
    Left = 22
    Top = 479
    Width = 131
    Height = 25
    Caption = 'Generate KeyPairs'
    TabOrder = 9
    OnClick = BtnGenerateKeyPairsClick
  end
end
