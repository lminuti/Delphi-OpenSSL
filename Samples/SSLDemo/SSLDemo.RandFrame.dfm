object RandomFrame: TRandomFrame
  Left = 0
  Top = 0
  Width = 320
  Height = 240
  TabOrder = 0
  object LabelSize: TLabel
    Left = 23
    Top = 27
    Width = 144
    Height = 13
    Caption = 'Random number len (in bytes)'
  end
  object EditSize: TEdit
    Left = 173
    Top = 24
    Width = 44
    Height = 21
    NumbersOnly = True
    TabOrder = 0
    Text = '20'
  end
  object EditResult: TEdit
    Left = 23
    Top = 88
    Width = 194
    Height = 21
    ReadOnly = True
    TabOrder = 1
  end
  object ButtonRandom: TButton
    Left = 23
    Top = 51
    Width = 194
    Height = 25
    Caption = 'Generate Random Numbers'
    TabOrder = 2
    OnClick = ButtonRandomClick
  end
end
