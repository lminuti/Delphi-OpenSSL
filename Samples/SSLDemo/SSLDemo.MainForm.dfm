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
    ActivePage = TabRandom
    Align = alClient
    TabOrder = 0
    object tabTutorial: TTabSheet
      Caption = 'Tutorial'
    end
    object tabRSABuffer: TTabSheet
      Caption = 'RSABuffer'
      ImageIndex = 1
    end
    object tabEncryption: TTabSheet
      Caption = 'Encryption'
      ImageIndex = 2
    end
    object TabRandom: TTabSheet
      Caption = 'Random'
      ImageIndex = 3
    end
  end
end
