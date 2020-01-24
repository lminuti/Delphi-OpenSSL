unit OpenSSL.CMSHeaders;

interface

uses
  IdSSLOpenSSLHeaders;

type
  {$IFDEF DEBUG_SAFESTACK}
    {$EXTERNALSYM STACK_OF_CMS_CertificateChoices}
    STACK_OF_CMS_CertificateChoices = record
      _stack: stack;
    end;
    {$EXTERNALSYM PSTACK_OF_CMS_CertificateChoices}
    PSTACK_OF_CMS_CertificateChoices = ^STACK_OF_CMS_CertificateChoices;

    {$EXTERNALSYM PSTACK_OF_CMS_RevocationInfoChoice}
    PSTACK_OF_CMS_RevocationInfoChoice = ^STACK_OF_CMS_RevocationInfoChoice;
    {$EXTERNALSYM STACK_OF_CMS_RevocationInfoChoice}
    STACK_OF_CMS_RevocationInfoChoice = record
      _stack: stack;
    end;

    {$EXTERNALSYM PSTACK_OF_CMS_RecipientInfo}
    PSTACK_OF_CMS_RecipientInfo = ^STACK_OF_CMS_RecipientInfo;
    {$EXTERNALSYM STACK_OF_CMS_RecipientInfo}
    STACK_OF_CMS_RecipientInfo = record
      _stack: stack;
    end;
  {$ELSE}
    {$EXTERNALSYM PSTACK_OF_CMS_CertificateChoices}
    PSTACK_OF_CMS_CertificateChoices = PSTACK;
    {$EXTERNALSYM PSTACK_OF_CMS_RevocationInfoChoice}
    PSTACK_OF_CMS_RevocationInfoChoice = PSTACK;
    {$EXTERNALSYM PSTACK_OF_CMS_RecipientInfo}
    PSTACK_OF_CMS_RecipientInfo = PSTACK;
  {$ENDIF}

  {$EXTERNALSYM PCMS_EncapsulatedContentInfo}
  PCMS_EncapsulatedContentInfo = ^CMS_EncapsulatedContentInfo;
  {$EXTERNALSYM CMS_EncapsulatedContentInfo}
  CMS_EncapsulatedContentInfo = record
    eContentType: PASN1_OBJECT;
    eContent: PASN1_OCTET_STRING;
    // Set to 1 if incomplete structure only part set up
    partial: Integer;
  end;

  {$EXTERNALSYM PCMS_SignedData}
  PCMS_SignedData = ^CMS_SignedData;
  {$EXTERNALSYM CMS_SignedData}
  CMS_SignedData = record
    version: Int32;
    digestAlgorithms: PSTACK_OF_X509_ALGOR;
    encapContentInfo: PCMS_EncapsulatedContentInfo;
    certificates: PSTACK_OF_CMS_CertificateChoices;
    crls: PSTACK_OF_CMS_RevocationInfoChoice;
    signerInfos: PSTACK_OF_CMS_SignerInfo;
  end;

  {$EXTERNALSYM PCMS_OriginatorInfo}
  PCMS_OriginatorInfo = ^CMS_OriginatorInfo;
  {$EXTERNALSYM CMS_OriginatorInfo}
  CMS_OriginatorInfo = record
    certificates: PSTACK_OF_CMS_CertificateChoices;
    crls: PSTACK_OF_CMS_RevocationInfoChoice;
  end;

  {$EXTERNALSYM PCMS_EncryptedContentInfo}
  PCMS_EncryptedContentInfo = ^CMS_EncryptedContentInfo;
  {$EXTERNALSYM CMS_EncryptedContentInfo}
  CMS_EncryptedContentInfo = record
    contentType: PASN1_OBJECT;
    contentEncryptionAlgorithm: PX509_ALGOR;
    encryptedContent: PASN1_OCTET_STRING;
    // Content encryption algorithm and key
    cipher: PEVP_CIPHER; //const ?
    key: PAnsiChar;
    keylen: Cardinal;
    //Set to 1 if we are debugging decrypt and don't fake keys for MMA
    debug: Integer;
    // Set to 1 if we have no cert and need extra safety measures for MMA
    havenocert: Integer;
  end;

  {$EXTERNALSYM PCMS_EnvelopedData}
  PCMS_EnvelopedData = ^CMS_EnvelopedData;
  {$EXTERNALSYM CMS_EnvelopedData}
  CMS_EnvelopedData = record
    version: Int32;
    originatorInfo: PCMS_OriginatorInfo;
    recipientInfos: PSTACK_OF_CMS_RecipientInfo;
    encryptedContentInfo: PCMS_EncryptedContentInfo;
    unprotectedAttrs: PSTACK_OF_X509_ATTRIBUTE;
  end;

  {$EXTERNALSYM PCMS_DigestedData}
  PCMS_DigestedData = ^CMS_DigestedData;
  {$EXTERNALSYM CMS_DigestedData}
  CMS_DigestedData = record
    version: Int32;
    digestAlgorithm: PX509_ALGOR;
    encapContentInfo: PCMS_EncapsulatedContentInfo;
    digest: PASN1_OCTET_STRING;
  end;

  {$EXTERNALSYM PCMS_EncryptedData}
  PCMS_EncryptedData = ^CMS_EncryptedData;
  {$EXTERNALSYM CMS_EncryptedData}
  CMS_EncryptedData = record
    version: Int32;
    encryptedContentInfo: PCMS_EncryptedContentInfo;
    unprotectedAttrs: PSTACK_OF_X509_ATTRIBUTE;
  end;

  {$EXTERNALSYM PCMS_AuthenticatedData}
  PCMS_AuthenticatedData = ^CMS_AuthenticatedData;
  {$EXTERNALSYM CMS_AuthenticatedData}
  CMS_AuthenticatedData = record
    version: Int32;
    originatorInfo: PCMS_OriginatorInfo;
    recipientInfos: PSTACK_OF_CMS_RecipientInfo;
    macAlgorithm: PX509_ALGOR;
    digestAlgorithm: PX509_ALGOR;
    encapContentInfo: PCMS_EncapsulatedContentInfo;
    authAttrs: PSTACK_OF_X509_ATTRIBUTE;
    mac: PASN1_OCTET_STRING;
    unauthAttrs: PSTACK_OF_X509_ATTRIBUTE;
  end;

  {$EXTERNALSYM PCMS_CompressedData}
  PCMS_CompressedData = ^CMS_CompressedData;
  {$EXTERNALSYM CMS_CompressedData}
  CMS_CompressedData = record
    version: Int32;
    compressionAlgorithm: PX509_ALGOR;
    recipientInfos: PSTACK_OF_CMS_RecipientInfo;
    encapContentInfo: PCMS_EncapsulatedContentInfo;
  end;

  {$EXTERNALSYM CMS_ContentInfo_union}
  CMS_ContentInfo_union = record
    case Integer of
      0 : (data: PASN1_OCTET_STRING);
      1 : (signedData: PCMS_SignedData);
      2 : (envelopedData: PCMS_EnvelopedData);
      3 : (digestedData: PCMS_DigestedData);
      4 : (encryptedData: PCMS_EncryptedData);
      5 : (authenticatedData: PCMS_AuthenticatedData);
      6 : (compressedData: PCMS_CompressedData);
      7 : (other: PASN1_TYPE);
      8 : (otherData: Pointer);
  end;

  {$EXTERNALSYM PCMS_ContentInfo}
  PCMS_ContentInfo = ^CMS_ContentInfo;
  {$EXTERNALSYM CMS_ContentInfo}
  CMS_ContentInfo = record
    contentType: PASN1_OBJECT;
    d: CMS_ContentInfo_union;
  end;

implementation

end.
