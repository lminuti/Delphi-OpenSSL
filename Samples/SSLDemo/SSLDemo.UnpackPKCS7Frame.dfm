object UnpackPKCS7Frame: TUnpackPKCS7Frame
  Left = 0
  Top = 0
  Width = 600
  Height = 341
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -15
  Font.Name = 'Segoe UI'
  Font.Style = []
  ParentFont = False
  TabOrder = 0
  DesignSize = (
    600
    341)
  object lblPKCS7File: TLabel
    Left = 3
    Top = 19
    Width = 69
    Height = 20
    Caption = 'PKCS7 file:'
  end
  object lblOutputFile: TLabel
    Left = 3
    Top = 70
    Width = 234
    Height = 20
    Anchors = [akLeft, akTop, akRight]
    Caption = 'Output file:'
  end
  object edtInputFileName: TEdit
    Left = 112
    Top = 16
    Width = 488
    Height = 28
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 0
    Text = 'edtInputFileName'
  end
  object edtOutputFileName: TEdit
    Left = 112
    Top = 67
    Width = 488
    Height = 28
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 1
    Text = 'edtInputFileName'
  end
  object btnUnpack: TButton
    AlignWithMargins = True
    Left = 112
    Top = 101
    Width = 431
    Height = 36
    Caption = 'Unpack'
    TabOrder = 2
    OnClick = btnUnpackClick
  end
  object chkVerify: TCheckBox
    Left = 3
    Top = 152
    Width = 270
    Height = 17
    Caption = 'Verify (no output data provided)'
    Checked = True
    State = cbChecked
    TabOrder = 3
  end
  object chkNoVerify: TCheckBox
    Left = 3
    Top = 184
    Width = 510
    Height = 33
    Caption = 
      'No verify (do not verify the signers certificate of a signed mes' +
      'sage)'
    Checked = True
    State = cbChecked
    TabOrder = 4
    WordWrap = True
  end
end
