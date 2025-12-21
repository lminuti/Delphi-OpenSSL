object RandomFrame: TRandomFrame
  Left = 0
  Top = 0
  Width = 320
  Height = 240
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -15
  Font.Name = 'Segoe UI'
  Font.Style = []
  ParentFont = False
  TabOrder = 0
  object LabelSize: TLabel
    Left = 23
    Top = 27
    Width = 200
    Height = 20
    Caption = 'Random number len (in bytes)'
  end
  object EditSize: TEdit
    Left = 229
    Top = 24
    Width = 44
    Height = 28
    NumbersOnly = True
    TabOrder = 0
    Text = '20'
  end
  object EditResult: TEdit
    Left = 23
    Top = 128
    Width = 250
    Height = 28
    ReadOnly = True
    TabOrder = 1
  end
  object ButtonRandom: TButton
    Left = 29
    Top = 75
    Width = 244
    Height = 30
    Caption = 'Generate Random Numbers'
    TabOrder = 2
    OnClick = ButtonRandomClick
  end
end
