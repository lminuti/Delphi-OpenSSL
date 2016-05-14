object MainForm: TMainForm
  Left = 0
  Top = 0
  Caption = 'SSLDemo'
  ClientHeight = 398
  ClientWidth = 691
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  PixelsPerInch = 96
  TextHeight = 13
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
    Width = 240
    Height = 13
    Caption = '1. Install OPENSSL and add it to your system path'
  end
  object Label3: TLabel
    Left = 24
    Top = 35
    Width = 252
    Height = 13
    Caption = '2. Go to the testdata folder and run create_cert.bat'
  end
  object Label4: TLabel
    Left = 24
    Top = 54
    Width = 201
    Height = 13
    Caption = '3. Check the the following file are created'
  end
  object Label5: TLabel
    Left = 24
    Top = 168
    Width = 106
    Height = 13
    Caption = '4. Generate a test file'
  end
  object Label6: TLabel
    Left = 24
    Top = 224
    Width = 171
    Height = 13
    Caption = '5. Try to encrypt with the cerificate'
  end
  object Label7: TLabel
    Left = 24
    Top = 274
    Width = 181
    Height = 13
    Caption = '6. Try to decrypt with the private key'
  end
  object Label8: TLabel
    Left = 24
    Top = 324
    Width = 174
    Height = 13
    Caption = '5. Try to encrypt with the public key'
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
    Text = 'edtCertFile'
  end
  object Button1: TButton
    Left = 24
    Top = 344
    Width = 131
    Height = 25
    Caption = 'Public Crypt'
    TabOrder = 2
    OnClick = Button1Click
  end
  object edtPriv: TEdit
    Left = 136
    Top = 107
    Width = 435
    Height = 21
    TabOrder = 3
    Text = 'edtCertFile'
  end
  object Button2: TButton
    Left = 24
    Top = 293
    Width = 131
    Height = 25
    Caption = 'Private decrypt'
    TabOrder = 4
    OnClick = Button2Click
  end
  object edtPub: TEdit
    Left = 136
    Top = 134
    Width = 435
    Height = 21
    TabOrder = 5
    Text = 'edtCertFile'
  end
  object Button3: TButton
    Left = 24
    Top = 243
    Width = 131
    Height = 25
    Caption = 'Public Crypt with cert'
    TabOrder = 6
    OnClick = Button3Click
  end
  object Button4: TButton
    Left = 495
    Top = 190
    Width = 75
    Height = 25
    Caption = 'Generate'
    TabOrder = 7
    OnClick = Button4Click
  end
end
