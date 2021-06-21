# the progress of the development

|num |  function   | is test ok |
|  ----  | ----  | ----  | 
| 1 |SDF_OpenDevice  | yes |
| 2 |SDF_CloseDevice  | yes |
| 3 |SDF_OpenSession  | yes |
| 4 |SDF_CloseSession  | yes |
| 5 |SDF_GetDeviceInfo  | yes |
| 6 |SDF_GenerateRandom  | yes |
| 7 |SDF_GetPrivateKeyAccessRight  | no |  
| 8 |SDF_ReleasePrivateKeyAccessRight  | yes | 
| 9 |SDF_ExportSignPublicKey_RSA  | yes |
| 10 |SDF_ExportEncPublicKey_RSA  | yes |
| 11 |SDF_GenerateKeyPair_RSA  | yes |
| 12 |SDF_GenerateKeyWithIPK_RSA  | no | 
| 13 |SDF_GenerateKeyWithEPK_RSA  | no | 
| 14 |SDF_ImportKeyWithISK_RSA  | no | !
| 15 |SDF_ExchangeDigitEnvelopeBaseOnRSA  | no | 
| 16 |SDF_ExportSignPublicKey_ECC  | yes |
| 17 |SDF_ExportEncPublicKey_ECC  | yes |
| 18 |SDF_GenerateKeyPair_ECC  | yes |
| 19 |SDF_GenerateKeyWithIPK_ECC  | yes | 
| 20 |SDF_GenerateKeyWithEPK_ECC  | yes | 
| 21 |SDF_ImportKeyWithISK_ECC  | yes |  
| 22 |SDF_GenerateAgreementDataWithECC  | yes | 有堆栈异常
| 23 |SDF_GenerateKeyWithECC  | yes | 
| 24 |SDF_GenerateAgreementDataAndKeyWithECC  | yes | 有堆栈异常
| 26 |SDF_ExchangeDigitEnvelopeBaseOnECC  | yes | 
| 27 |SDF_ImportKeyWithKEK  | no |  
| 28 |SDF_ImportKey  | yes |
| 29 |SDF_DestroyKey  | yes |
| 30 |SDF_ExternalPublicKeyOperation_RSA  | yes |  
| 31 |SDF_ExternalPrivateKeyOperation_RSA  | yes |  有堆栈异常
| 32 |SDF_InternalPublicKeyOperation_RSA  | yes  | 
| 33 |SDF_InternalPrivateKeyOperation_RSA  | yes | 有堆栈异常
| 34 |SDF_ExternalSign_ECC  | yes |
| 35 |SDF_ExternalVerify_ECC  | yes |
| 36 |SDF_InternalSign_ECC  | yes|
| 37 |SDF_InternalVerify_ECC  | yes |
| 38 |SDF_ExternalEncrypt_ECC  | yes |  
| 39 |SDF_ExternalDecrypt_ECC  | yes |  
| 40 |SDF_Encrypt  | yes(仅支持SGD_SMS4_ECB)  |　　　　
| 41 |SDF_Decrypt  | yes(仅支持SGD_SMS4_ECB)  |
| 42 |SDF_CalculateMAC  | yes |
| 43 |SDF_HashInit  | yes|
| 44 |SDF_HashUpdate  | yes |
| 45 |SDF_HashFinal  | yes |
| 46 |SDF_CreateFile  | yes |
| 47 |SDF_ReadFile  |yes | 
| 48 |SDF_WriteFile  | yes | 
| 49 |SDF_DeleteFile  | yes |









    
    
    
    
    