object UnpackPKCS7Frame: TUnpackPKCS7Frame
  Left = 0
  Top = 0
  Width = 440
  Height = 267
  TabOrder = 0
  DesignSize = (
    440
    267)
  object lblPKCS7File: TLabel
    Left = 3
    Top = 19
    Width = 52
    Height = 13
    Caption = 'PKCS7 file:'
  end
  object lblOutputFile: TLabel
    Left = 3
    Top = 46
    Width = 55
    Height = 13
    Anchors = [akLeft, akTop, akRight]
    Caption = 'Output file:'
  end
  object edtInputFileName: TEdit
    Left = 60
    Top = 16
    Width = 374
    Height = 21
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 0
    Text = 'edtInputFileName'
  end
  object edtOutputFileName: TEdit
    Left = 60
    Top = 43
    Width = 374
    Height = 21
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 1
    Text = 'edtInputFileName'
  end
  object btnUnpack: TButton
    AlignWithMargins = True
    Left = 3
    Top = 70
    Width = 431
    Height = 25
    Caption = 'Unpack'
    TabOrder = 2
    OnClick = btnUnpackClick
  end
  object chkVerify: TCheckBox
    Left = 3
    Top = 120
    Width = 182
    Height = 17
    Caption = 'Verify (no output data provided)'
    Checked = True
    State = cbChecked
    TabOrder = 3
  end
  object chkNoVerify: TCheckBox
    Left = 221
    Top = 112
    Width = 213
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
