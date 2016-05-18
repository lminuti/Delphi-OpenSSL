object EncFrame: TEncFrame
  Left = 0
  Top = 0
  Width = 388
  Height = 266
  TabOrder = 0
  DesignSize = (
    388
    266)
  object Label1: TLabel
    Left = 3
    Top = 131
    Width = 47
    Height = 13
    Caption = 'Input file:'
  end
  object Label2: TLabel
    Left = 3
    Top = 158
    Width = 123
    Height = 13
    Anchors = [akLeft, akTop, akRight]
    Caption = 'Output file:'
    ExplicitWidth = 55
  end
  object btnEncrypt: TButton
    Left = 3
    Top = 184
    Width = 142
    Height = 25
    Caption = 'Encrypt'
    TabOrder = 0
    OnClick = btnEncryptClick
  end
  object memTest: TMemo
    AlignWithMargins = True
    Left = 3
    Top = 3
    Width = 382
    Height = 89
    Align = alTop
    Lines.Strings = (
      'Hello, world!')
    TabOrder = 1
    ExplicitWidth = 314
  end
  object btnDecrypt: TButton
    Left = 151
    Top = 184
    Width = 142
    Height = 25
    Caption = 'Decrypt'
    TabOrder = 2
    OnClick = btnDecryptClick
  end
  object edtInputFileName: TEdit
    Left = 64
    Top = 128
    Width = 321
    Height = 21
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 3
    Text = 'edtInputFileName'
    ExplicitWidth = 253
  end
  object edtOutputFileName: TEdit
    Left = 64
    Top = 155
    Width = 321
    Height = 21
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 4
    Text = 'edtInputFileName'
    ExplicitWidth = 253
  end
  object chkBase64: TCheckBox
    Left = 8
    Top = 222
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
    Width = 382
    Height = 25
    Align = alTop
    Caption = 'Create test file from memo'
    TabOrder = 6
    OnClick = BtnGenrateFileClick
    ExplicitWidth = 313
  end
end
