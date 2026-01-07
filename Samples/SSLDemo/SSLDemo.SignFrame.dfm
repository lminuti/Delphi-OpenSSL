object SignFrame: TSignFrame
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
    Width = 74
    Height = 20
    Anchors = [akLeft, akTop, akRight]
    Caption = 'Output file:'
  end
  object btnSign: TButton
    Left = 3
    Top = 279
    Width = 142
    Height = 32
    Caption = 'Sign'
    TabOrder = 0
    OnClick = btnSignClick
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
  end
  object btnVerify: TButton
    Left = 151
    Top = 279
    Width = 142
    Height = 34
    Caption = 'Verify'
    TabOrder = 2
    OnClick = btnVerifyClick
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
  object BtnGenrateFile: TButton
    AlignWithMargins = True
    Left = 3
    Top = 98
    Width = 679
    Height = 35
    Align = alTop
    Caption = 'Create test file from memo'
    TabOrder = 5
    OnClick = BtnGenrateFileClick
  end
end
