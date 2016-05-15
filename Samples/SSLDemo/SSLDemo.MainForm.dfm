object MainForm: TMainForm
  Left = 0
  Top = 0
  Caption = 'SSLDemo'
  ClientHeight = 544
  ClientWidth = 613
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
  object pgcMain: TPageControl
    Left = 0
    Top = 0
    Width = 613
    Height = 544
    ActivePage = tabRSABuffer
    Align = alClient
    TabOrder = 0
    ExplicitHeight = 445
    object tabTutorial: TTabSheet
      Caption = 'Tutorial'
      ExplicitWidth = 591
      ExplicitHeight = 370
    end
    object tabRSABuffer: TTabSheet
      Caption = 'RSABuffer'
      ImageIndex = 1
      ExplicitWidth = 591
      ExplicitHeight = 370
    end
  end
end
