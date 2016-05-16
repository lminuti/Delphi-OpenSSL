object EncFrame: TEncFrame
  Left = 0
  Top = 0
  Width = 320
  Height = 240
  TabOrder = 0
  DesignSize = (
    320
    240)
  object Label1: TLabel
    Left = 3
    Top = 101
    Width = 47
    Height = 13
    Caption = 'Input file:'
  end
  object Label2: TLabel
    Left = 3
    Top = 128
    Width = 55
    Height = 13
    Anchors = [akLeft, akTop, akRight]
    Caption = 'Output file:'
  end
  object btnEncrypt: TButton
    Left = 3
    Top = 154
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
    Width = 314
    Height = 89
    Align = alTop
    Lines.Strings = (
      'Hello, world!')
    TabOrder = 1
    ExplicitLeft = 24
    ExplicitTop = 17
    ExplicitWidth = 185
  end
  object btnDecrypt: TButton
    Left = 151
    Top = 154
    Width = 142
    Height = 25
    Caption = 'Decrypt'
    TabOrder = 2
    OnClick = btnDecryptClick
  end
  object edtInputFileName: TEdit
    Left = 64
    Top = 98
    Width = 253
    Height = 21
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 3
    Text = 'edtInputFileName'
  end
  object edtOutputFileName: TEdit
    Left = 64
    Top = 125
    Width = 253
    Height = 21
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 4
    Text = 'edtInputFileName'
  end
end
