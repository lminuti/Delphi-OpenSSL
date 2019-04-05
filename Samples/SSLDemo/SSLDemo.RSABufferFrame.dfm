object RSABufferFrame: TRSABufferFrame
  Left = 0
  Top = 0
  Width = 451
  Height = 621
  Align = alClient
  AutoScroll = True
  TabOrder = 0
  ExplicitHeight = 305
  object grpPublicKey: TGroupBox
    AlignWithMargins = True
    Left = 3
    Top = 3
    Width = 428
    Height = 254
    Align = alTop
    Caption = 'Public key'
    TabOrder = 0
    object btnLoadPubKeyIntoMem: TButton
      Left = 16
      Top = 13
      Width = 385
      Height = 25
      Caption = 'Load public key into memo'
      TabOrder = 0
      OnClick = btnLoadPubKeyIntoMemClick
    end
    object btnLoadPublicKey: TButton
      Left = 16
      Top = 215
      Width = 257
      Height = 25
      Caption = 'Load memo into TRSAPublicKey'
      TabOrder = 1
      OnClick = btnLoadPublicKeyClick
    end
    object edtPub: TEdit
      Left = 16
      Top = 44
      Width = 385
      Height = 21
      TabOrder = 2
    end
    object memPub: TMemo
      Left = 16
      Top = 71
      Width = 385
      Height = 138
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -12
      Font.Name = 'Courier New'
      Font.Style = []
      Lines.Strings = (
        'memPub')
      ParentFont = False
      ScrollBars = ssBoth
      TabOrder = 3
      WordWrap = False
    end
    object cmbPublicKeyFormat: TComboBox
      Left = 279
      Top = 217
      Width = 122
      Height = 21
      Style = csDropDownList
      ItemIndex = 0
      TabOrder = 4
      Text = 'Default'
      Items.Strings = (
        'Default'
        'RSAPublicKey')
    end
  end
  object grpPrivateKey: TGroupBox
    AlignWithMargins = True
    Left = 3
    Top = 263
    Width = 428
    Height = 254
    Align = alTop
    Caption = 'Private key'
    TabOrder = 1
    object btnLoadPrivKeyIntoMemo: TButton
      Left = 16
      Top = 13
      Width = 385
      Height = 25
      Caption = 'Load private key into memo'
      TabOrder = 0
      OnClick = btnLoadPrivKeyIntoMemoClick
    end
    object btnLoadPrivateKey: TButton
      Left = 16
      Top = 215
      Width = 257
      Height = 25
      Caption = 'Load memo into TRSAPrivateKey'
      TabOrder = 1
      OnClick = btnLoadPrivateKeyClick
    end
    object edtPriv: TEdit
      Left = 16
      Top = 44
      Width = 385
      Height = 21
      TabOrder = 2
    end
    object memPriv: TMemo
      Left = 16
      Top = 71
      Width = 385
      Height = 138
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -12
      Font.Name = 'Courier New'
      Font.Style = []
      Lines.Strings = (
        'memPriv')
      ParentFont = False
      ScrollBars = ssBoth
      TabOrder = 3
      WordWrap = False
    end
    object cmbPrivateKeyFormat: TComboBox
      Left = 279
      Top = 217
      Width = 122
      Height = 21
      Style = csDropDownList
      ItemIndex = 0
      TabOrder = 4
      Text = 'Default'
      Items.Strings = (
        'Default'
        'RSAPrivateKey')
    end
  end
  object grpCertificate: TGroupBox
    AlignWithMargins = True
    Left = 3
    Top = 523
    Width = 428
    Height = 254
    Align = alTop
    Caption = 'Certificate'
    TabOrder = 2
    object btnLoadCertIntoMemo: TButton
      Left = 16
      Top = 16
      Width = 385
      Height = 25
      Caption = 'Load certificate into memo'
      TabOrder = 0
      OnClick = btnLoadCertIntoMemoClick
    end
    object btnLoadCert: TButton
      Left = 16
      Top = 215
      Width = 385
      Height = 25
      Caption = 'Load memo into TX509Cerificate'
      TabOrder = 1
      OnClick = btnLoadCertClick
    end
    object edtCert: TEdit
      Left = 16
      Top = 44
      Width = 385
      Height = 21
      TabOrder = 2
    end
    object memCert: TMemo
      Left = 16
      Top = 71
      Width = 385
      Height = 138
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -12
      Font.Name = 'Courier New'
      Font.Style = []
      Lines.Strings = (
        'memCert')
      ParentFont = False
      ScrollBars = ssBoth
      TabOrder = 3
      WordWrap = False
    end
  end
end
