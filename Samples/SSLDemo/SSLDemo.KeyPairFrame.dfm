object KeyPairFrame: TKeyPairFrame
  Left = 0
  Top = 0
  Width = 468
  Height = 396
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -15
  Font.Name = 'Segoe UI'
  Font.Style = []
  ParentFont = False
  TabOrder = 0
  object btnKeyPairGen: TButton
    Left = 72
    Top = 48
    Width = 201
    Height = 41
    Caption = 'Generate key pair'
    TabOrder = 0
    OnClick = btnKeyPairGenClick
  end
end
