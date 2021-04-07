# the progress of the development

|  function   | is test ok |
|  ----  | ----  |
| SDF_OpenDevice  | ok |
| SDF_CloseDevice  | ok |
| SDF_OpenSession  | ok |
| SDF_CloseSession  | ok |
| SDF_GetDeviceInfo  | ok |
| SDF_GenerateRandom  | ok |
| SDF_GetPrivateKeyAccessRight  | no |
| SDF_ReleasePrivateKeyAccessRight  | ok |
| SDF_ExportSignPublicKey_RSA  | ok(wait for verification) |
| SDF_ExportEncPublicKey_RSA  | ok(wait for verification) |
| SDF_GenerateKeyPair_RSA  | ok |
| SDF_GenerateKeyWithIPK_RSA  | ok |
| SDF_GenerateKeyWithEPK_RSA  | ok |
| SDF_ImportKeyWithISK_RSA  | no |
| SDF_ExchangeDigitEnvelopeBaseOnRSA  | no |
| SDF_ExportSignPublicKey_ECC  | ok(需要进一步测试) |
| SDF_ExportEncPublicKey_ECC  | ok(需要进一步测试) |
| SDF_GenerateKeyPair_ECC  | ok(需要进一步测试) |
| SDF_GenerateKeyWithIPK_ECC  | ok |
| SDF_GenerateKeyWithEPK_ECC  | ok(需要进一步测试) |
| SDF_ImportKeyWithISK_ECC  | no |
| SDF_GenerateAgreementDataWithECC  | no |
| SDF_GenerateKeyWithECC  | no |
| SDF_GenerateAgreementDataAndKeyWithECC  | no |
| SDF_ExchangeDigitEnvelopeBaseOnECC  | no |
| SDF_ImportKeyWithKEK  | no |
| SDF_DestroyKey  | ok |
| SDF_ExternalPublicKeyOperation_RSA  | no |
| SDF_InternalPublicKeyOperation_RSA  | ok(指针未能释放)  |
| SDF_InternalPrivateKeyOperation_RSA  | ok(指针未能释放) |
| SDF_ExternalVerify_ECC  | no |
| SDF_InternalSign_ECC  | ok(需要进一步测试)|
| SDF_InternalVerify_ECC  | ok |
| SDF_ExternalEncrypt_ECC  | no |
| SDF_Encrypt  | ok(CBC验证不通过)  |　　　　
| SDF_Decrypt  | ok |
| SDF_CalculateMAC  | ok |
| SDF_CreateFile  | ok |
| SDF_ReadFile  | !（人类未解之谜） |
| SDF_WriteFile  | !（人类未解之谜） |
| SDF_DeleteFile  | ok |
| SDF_HashInit  | ok(等待SM3规范测试) |
| SDF_HashUpdate  | ok |
| SDF_HashFinal  | ok |
| SDF_GetSymmKeyHandle  | no |
| SDF_ImportKey  | ok |
| SDF_ExternalPrivateKeyOperation_RSA  | no |
| SDF_ExternalSign_ECC  | no |
| SDF_ExternalDecrypt_ECC  | no |
| SDF_InternalDecrypt_ECC  | ok |
| SDF_InternalEncrypt_ECC  | ok |
| SDF_ExportKeyWithEPK_RSA  | no |
| SDF_ExportKeyWithEPK_ECC  | no |
| SDF_ExportKeyWithKEK  | no |
| SDF_ExportSignMasterPublicKey_SM9  | no |
| SDF_ExportEncMasterPublicKey_SM9  | no |
| SDF_ExportSignMasterKeyPairG_SM9  | no |
| SDF_ExportEncMasterKeyPairG_SM9  | no |
| SDF_ImportUserSignPrivateKey_SM9  | no |
| SDF_ImportUserEncPrivateKey_SM9  | no |
| SDF_GenerateSignUserPrivateKey_SM9  | no |
| SDF_GenerateEncUserPrivateKey_SM9  | no |
| SDF_Sign_SM9  | no |
| SDF_SignEx_SM9  | no |
| SDF_Verify_SM9  | no |
| SDF_VerifyEx_SM9  | no |
| SDF_Encrypt_SM9  | no |
| SDF_EncryptEx_SM9  | no |
| SDF_Decrypt_SM9  | no |
| SDF_Encap_SM9  | no |
| SDF_Decap_SM9  | no |
| SDF_GenerateAgreementDataWithSM9  | no |
| SDF_GenerateAgreemetDataAndKeyWithSM9  | no |
| SDF_GenerateKeyWithSM9  | no |
| SDF_GenerateKeyVerifySM9  | no |







    
    
    
    
    