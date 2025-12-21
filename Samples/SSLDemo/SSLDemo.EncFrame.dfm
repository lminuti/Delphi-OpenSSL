object EncFrame: TEncFrame
  Left = 0
  Top = 0
  Width = 685
  Height = 455
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -15
  Font.Name = 'Segoe UI'
  Font.Style = []
  ParentFont = False
  TabOrder = 0
  DesignSize = (
    685
    455)
  object Label1: TLabel
    Left = 3
    Top = 155
    Width = 62
    Height = 20
    Caption = 'Input file:'
  end
  object Label2: TLabel
    Left = 3
    Top = 197
    Width = 371
    Height = 20
    Anchors = [akLeft, akTop, akRight]
    Caption = 'Output file:'
  end
  object Label3: TLabel
    Left = 3
    Top = 240
    Width = 43
    Height = 20
    Caption = 'Cipher'
  end
  object btnEncrypt: TButton
    Left = 3
    Top = 279
    Width = 142
    Height = 32
    Caption = 'Encrypt'
    TabOrder = 0
    OnClick = btnEncryptClick
  end
  object memTest: TMemo
    AlignWithMargins = True
    Left = 3
    Top = 3
    Width = 679
    Height = 89
    Align = alTop
    Lines.Strings = (
      'Hello, world!')
    TabOrder = 1
    ExplicitWidth = 382
  end
  object btnDecrypt: TButton
    Left = 151
    Top = 279
    Width = 142
    Height = 34
    Caption = 'Decrypt'
    TabOrder = 2
    OnClick = btnDecryptClick
  end
  object edtInputFileName: TEdit
    Left = 104
    Top = 152
    Width = 576
    Height = 28
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 3
    Text = 'edtInputFileName'
  end
  object edtOutputFileName: TEdit
    Left = 104
    Top = 194
    Width = 578
    Height = 28
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 4
    Text = 'edtInputFileName'
  end
  object chkBase64: TCheckBox
    Left = 8
    Top = 317
    Width = 97
    Height = 17
    Caption = 'Use base64'
    Checked = True
    State = cbChecked
    TabOrder = 5
  end
  object BtnGenrateFile: TButton
    AlignWithMargins = True
    Left = 3
    Top = 98
    Width = 679
    Height = 35
    Align = alTop
    Caption = 'Create test file from memo'
    TabOrder = 6
    OnClick = BtnGenrateFileClick
  end
  object cmbCipher: TComboBox
    Left = 104
    Top = 237
    Width = 578
    Height = 28
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 7
  end
end
