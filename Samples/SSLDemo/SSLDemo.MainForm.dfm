object MainForm: TMainForm
  Left = 0
  Top = 0
  Caption = 'SSLDemo'
  ClientHeight = 635
  ClientWidth = 847
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -13
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poScreenCenter
  OnCreate = FormCreate
  TextHeight = 17
  object pgcMain: TPageControl
    Left = 0
    Top = 0
    Width = 847
    Height = 616
    Align = alClient
    TabOrder = 0
    ExplicitHeight = 635
  end
  object StatusBar1: TStatusBar
    Left = 0
    Top = 616
    Width = 847
    Height = 19
    Panels = <
      item
        Width = 50
      end>
    ExplicitTop = 622
  end
end
