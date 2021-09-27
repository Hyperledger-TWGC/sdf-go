// Package sdf
//Copyright Hyperledger All Rights Reserved.
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//                 http://www.apache.org/licenses/LICENSE-2.0
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
package sdf

/*
#cgo windows CFLAGS: -DPACKED_STRUCTURES
#cgo linux LDFLAGS: -ldl
#cgo darwin LDFLAGS: -ldl
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sansec/swsds.h>


SGD_HANDLE hDeviceHandle;
SGD_HANDLE hSessionHandle;

typedef unsigned char     SGD_UCHAR;
typedef unsigned char*    SGD_UCHAR_PRT;


#ifdef _WIN32
#include<windows.h>

struct LibHandle {
	HMODULE handle;
};



struct LibHandle *New(const char *iLibrary)
{
	struct LibHandle *h = calloc(1,sizeof(struct LibHandle));
	h->handle = LoadLibrary(iLibrary);
	if (h->handle == NULL) {
		free(h);
		return NULL;
	}

	return h;
}

void Destroy(struct LibHandle *h)
{
	if(!h){
		return ;
	}
    if (h->handle == NULL) {
		return;
	}
	free(h);

}

#else
#include <dlfcn.h>

struct LibHandle {
	void *handle;
};

struct LibHandle *New(const char *iLibrary)
{

	struct LibHandle *h = calloc(1,sizeof(struct LibHandle));
	h->handle = dlopen(iLibrary,1);
	if(h->handle == NULL){
		free(h);
		return NULL;
	}
	return h;
}




void Destroy(struct LibHandle *h)
{
	if (!h) {
		return;
	}
	if (h->handle == NULL) {
		return;
	}
	if (dlclose(h->handle) < 0) {
		return;
	}
	free(h);
}

#endif
//1. 打开设备
SGD_RV SDFOpenDevice(struct LibHandle * h,SGD_HANDLE *phDeviceHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE*);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_OpenDevice");
	return (*fptr)(phDeviceHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_OpenDevice");
	return (*fptr)(phDeviceHandle);
#endif
}
//2. 关闭设备
SGD_RV SDFCloseDevice(struct LibHandle * h,SGD_HANDLE hDeviceHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_CloseDevice");
	return (*fptr)(hDeviceHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_CloseDevice");
	return (*fptr)(hDeviceHandle);
#endif
}
//3. 创建会话
SGD_RV SDFOpenSession(struct LibHandle * h,SGD_HANDLE hDeviceHandle, SGD_HANDLE *phSessionHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_HANDLE *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_OpenSession");
	return (*fptr)(hDeviceHandle,phSessionHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_OpenSession");
	return (*fptr)(hDeviceHandle,phSessionHandle);
#endif
}
//4. 关闭会话
SGD_RV SDFCloseSession(struct LibHandle * h,SGD_HANDLE hSessionHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_CloseSession");
	return (*fptr)(hSessionHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_CloseSession");
	return (*fptr)(hSessionHandle);
#endif
}
//5. 获取设备信息
SGD_RV SDFGetDeviceInfo(struct LibHandle * h,SGD_HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,DEVICEINFO *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GetDeviceInfo");
	return (*fptr)(hSessionHandle,pstDeviceInfo);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GetDeviceInfo");
	return (*fptr)(hSessionHandle,pstDeviceInfo);
#endif
}
//6. 产生随机数
SGD_RV SDFGenerateRandom(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiLength, SGD_UCHAR_PRT *pucRandom)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,SGD_UCHAR*);
	*pucRandom = calloc(uiLength, sizeof(SGD_UCHAR));
	if (*pucRandom == NULL) {
		return SGD_FALSE;
	}
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateRandom");
	return (*fptr)(hSessionHandle,uiLength,*pucRandom);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateRandom");
	return (*fptr)(hSessionHandle,uiLength,*pucRandom);
#endif
}
//7. 获取私钥使用权限
SGD_RV SDFGetPrivateKeyAccessRight(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex,SGD_UCHAR_PRT pucPassword, SGD_UINT32  uiPwdLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,SGD_UCHAR*,SGD_UINT32);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GetPrivateKeyAccessRight");
	return (*fptr)(hSessionHandle,uiKeyIndex,pucPassword,uiPwdLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GetPrivateKeyAccessRight");
	return (*fptr)(hSessionHandle,uiKeyIndex,pucPassword,uiPwdLength);
#endif
}
//8. 释放私钥使用权限
SGD_RV SDFReleasePrivateKeyAccessRight(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ReleasePrivateKeyAccessRight");
	return (*fptr)(hSessionHandle,uiKeyIndex);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ReleasePrivateKeyAccessRight");
	return (*fptr)(hSessionHandle,uiKeyIndex);
#endif
}
//9. 导出RSA签名公钥
SGD_RV SDFExportSignPublicKey_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,RSArefPublicKey*);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExportSignPublicKey_RSA");
	return (*fptr)(hSessionHandle,uiKeyIndex,pucPublicKey);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExportSignPublicKey_RSA");
	return (*fptr)(hSessionHandle,uiKeyIndex,pucPublicKey);
#endif
}
//10. 导出RSA加密公钥
SGD_RV SDFExportEncPublicKey_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,RSArefPublicKey*);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExportEncPublicKey_RSA");
	return (*fptr)(hSessionHandle,uiKeyIndex,pucPublicKey);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExportEncPublicKey_RSA");
	return (*fptr)(hSessionHandle,uiKeyIndex,pucPublicKey);
#endif
}
//11. 产生RSA非对称密钥对并输出
SGD_RV SDFGenerateKeyPair_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyBits,RSArefPublicKey *pucPublicKey,RSArefPrivateKey *pucPrivateKey)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,RSArefPublicKey*,RSArefPrivateKey*);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateKeyPair_RSA");
	return (*fptr)(hSessionHandle,uiKeyBits,pucPublicKey,pucPrivateKey);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateKeyPair_RSA");
	return (*fptr)(hSessionHandle,uiKeyBits,pucPublicKey,pucPrivateKey);
#endif
}
//12. 生成会话密钥并用内部RSA公钥加密输出
SGD_RV SDFGenerateKeyWithIPK_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR_PRT *pucKey,SGD_UINT32 *puiKeyLength,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,SGD_UINT32,SGD_UCHAR*,SGD_UINT32*,SGD_HANDLE*);
	*pucKey = calloc(*puiKeyLength, sizeof(SGD_UCHAR));
	if (*pucKey == NULL) {
		return SGD_FALSE;
	}
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateKeyWithIPK_RSA");
	return (*fptr)(hSessionHandle,uiIPKIndex,uiKeyBits,*pucKey,puiKeyLength,phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateKeyWithIPK_RSA");
	return (*fptr)(hSessionHandle,uiIPKIndex,uiKeyBits,*pucKey,puiKeyLength,phKeyHandle);
#endif
}
//13. 生成会话密钥并用外部RSA公钥加密输出
SGD_RV SDFGenerateKeyWithEPK_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits,RSArefPublicKey *pucPublicKey,SGD_UCHAR_PRT *pucKey,SGD_UINT32 *puiKeyLength,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,RSArefPublicKey*,SGD_UCHAR*,SGD_UINT32*,SGD_HANDLE*);
	*pucKey = calloc(*puiKeyLength, sizeof(SGD_UCHAR));
	if (*pucKey == NULL) {
		return SGD_FALSE;
	}
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateKeyWithEPK_RSA");
	return (*fptr)(hSessionHandle,uiKeyBits,pucPublicKey,*pucKey,puiKeyLength,phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle,"SDF_GenerateKeyWithEPK_RSA");
	return (*fptr)(hSessionHandle,uiKeyBits,pucPublicKey,*pucKey,puiKeyLength,phKeyHandle);
#endif
}
//14. 导入会话密钥并用内部RSA私钥解密
SGD_RV SDFImportKeyWithISK_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,SGD_UCHAR_PRT pucKey,SGD_UINT32 uiKeyLength,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,SGD_UCHAR*,SGD_UINT32,SGD_HANDLE*);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ImportKeyWithISK_RSA");
	return (*fptr)(hSessionHandle,uiISKIndex,pucKey,uiKeyLength,phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ImportKeyWithISK_RSA");
	return (*fptr)(hSessionHandle,uiISKIndex,pucKey,uiKeyLength,phKeyHandle);
#endif
}
//15. 基于RSA算法的数字信封转换
SGD_RV SDFExchangeDigitEnvelopeBaseOnRSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey,SGD_UCHAR_PRT pucDEInput,SGD_UINT32  uiDELength,SGD_UCHAR_PRT *pucDEOutput,SGD_UINT32  *puiDELength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,RSArefPublicKey*,SGD_UCHAR*,SGD_UINT32,SGD_UCHAR*,SGD_UINT32*);
	*pucDEOutput = calloc(*puiDELength, sizeof(SGD_UCHAR));
	if (*pucDEOutput == NULL) {
		return SGD_FALSE;
	}
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExchangeDigitEnvelopeBaseOnRSA");
	return (*fptr)(hSessionHandle,uiKeyIndex,pucPublicKey,pucDEInput,uiDELength,*pucDEOutput,puiDELength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExchangeDigitEnvelopeBaseOnRSA");
	return (*fptr)(hSessionHandle,uiKeyIndex,pucPublicKey,pucDEInput,uiDELength,*pucDEOutput,puiDELength);
#endif
}
//16. 导出ECC签名公钥
SGD_RV SDFExportSignPublicKey_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,ECCrefPublicKey *pucPublicKey)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,ECCrefPublicKey*);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExportSignPublicKey_ECC");
	return (*fptr)(hSessionHandle,uiKeyIndex,pucPublicKey);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExportSignPublicKey_ECC");
	return (*fptr)(hSessionHandle,uiKeyIndex,pucPublicKey);
#endif
}
//17. 导出ECC加密公钥
SGD_RV SDFExportEncPublicKey_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,ECCrefPublicKey *pucPublicKey)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,ECCrefPublicKey*);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExportEncPublicKey_ECC");
	return (*fptr)(hSessionHandle,uiKeyIndex,pucPublicKey);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExportEncPublicKey_ECC");
	return (*fptr)(hSessionHandle,uiKeyIndex,pucPublicKey);
#endif
}
//18. 产生ECC非对称密钥对并输出
SGD_RV SDFGenerateKeyPair_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiAlgID,SGD_UINT32  uiKeyBits,ECCrefPublicKey *pucPublicKey,ECCrefPrivateKey *pucPrivateKey)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,SGD_UINT32,ECCrefPublicKey*,ECCrefPrivateKey*);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateKeyPair_ECC");
	return (*fptr)(hSessionHandle,uiAlgID,uiKeyBits,pucPublicKey,pucPrivateKey);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateKeyPair_ECC");
	return (*fptr)(hSessionHandle,uiAlgID,uiKeyBits,pucPublicKey,pucPrivateKey);
#endif
}
//19. 生成会话密钥并用内部ECC公钥加密输出
SGD_RV SDFGenerateKeyWithIPK_ECC (struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex,SGD_UINT32 uiKeyBits,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,SGD_UINT32,ECCCipher*,SGD_HANDLE*);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateKeyWithIPK_ECC");
	return (*fptr)(hSessionHandle,uiIPKIndex,uiKeyBits,pucKey,phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateKeyWithIPK_ECC");
	return (*fptr)(hSessionHandle,uiIPKIndex,uiKeyBits,pucKey,phKeyHandle);
#endif
}
//20. 生成会话密钥并用外部ECC公钥加密输出
SGD_RV SDFGenerateKeyWithEPK_ECC (struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits,SGD_UINT32  uiAlgID,ECCrefPublicKey *pucPublicKey,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,SGD_UINT32,ECCrefPublicKey*,ECCCipher*,SGD_HANDLE*);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateKeyWithEPK_ECC");
	return (*fptr)(hSessionHandle,uiKeyBits,uiAlgID,pucPublicKey,pucKey,phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateKeyWithEPK_ECC");
	return (*fptr)(hSessionHandle,uiKeyBits,uiAlgID,pucPublicKey,pucKey,phKeyHandle);
#endif
}
//21. 导入会话密钥并用内部ECC私钥解密
SGD_RV SDFImportKeyWithISK_ECC (struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiISKIndex,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,ECCCipher*,SGD_HANDLE*);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ImportKeyWithISK_ECC");
	return (*fptr)(hSessionHandle,uiISKIndex,pucKey,phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ImportKeyWithISK_ECC");
	return (*fptr)(hSessionHandle,uiISKIndex,pucKey,phKeyHandle);
#endif
}
//22. 生成密钥协商参数并输出
SGD_RV SDFGenerateAgreementDataWithECC (struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR_PRT pucSponsorID,SGD_UINT32 uiSponsorIDLength,ECCrefPublicKey  *pucSponsorPublicKey,ECCrefPublicKey  *pucSponsorTmpPublicKey,SGD_HANDLE *phAgreementHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UINT32 ,SGD_UINT32 ,SGD_UCHAR *,SGD_UINT32 ,ECCrefPublicKey  *,ECCrefPublicKey  *,SGD_HANDLE *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateAgreementDataWithECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, uiKeyBits, pucSponsorID, uiSponsorIDLength,  pucSponsorPublicKey,  pucSponsorTmpPublicKey, phAgreementHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateAgreementDataWithECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, uiKeyBits, pucSponsorID, uiSponsorIDLength,  pucSponsorPublicKey,  pucSponsorTmpPublicKey, phAgreementHandle);
#endif
}
//23. 计算会话密钥
SGD_RV SDFGenerateKeyWithECC (struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UCHAR_PRT pucResponseID,SGD_UINT32 uiResponseIDLength,ECCrefPublicKey *pucResponsePublicKey,ECCrefPublicKey *pucResponseTmpPublicKey,SGD_HANDLE hAgreementHandle,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE, SGD_UCHAR *,SGD_UINT32 ,ECCrefPublicKey *,ECCrefPublicKey *,SGD_HANDLE ,SGD_HANDLE *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateKeyWithECC");
	return (*fptr)(hSessionHandle,pucResponseID,uiResponseIDLength,pucResponsePublicKey,pucResponseTmpPublicKey,hAgreementHandle,phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateKeyWithECC");
	return (*fptr)(hSessionHandle,pucResponseID,uiResponseIDLength,pucResponsePublicKey,pucResponseTmpPublicKey,hAgreementHandle,phKeyHandle);
#endif
}
//24. 产生协商数据并计算会话密钥
SGD_RV SDFGenerateAgreementDataAndKeyWithECC (struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR_PRT pucResponseID,SGD_UINT32 uiResponseIDLength,SGD_UCHAR_PRT pucSponsorID,SGD_UINT32 uiSponsorIDLength,ECCrefPublicKey *pucSponsorPublicKey,ECCrefPublicKey *pucSponsorTmpPublicKey,ECCrefPublicKey  *pucResponsePublicKey,	ECCrefPublicKey  *pucResponseTmpPublicKey,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UINT32 ,SGD_UINT32 ,SGD_UCHAR *,SGD_UINT32 ,SGD_UCHAR *,SGD_UINT32 ,ECCrefPublicKey *,ECCrefPublicKey *,ECCrefPublicKey  *,	ECCrefPublicKey  *,SGD_HANDLE *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateAgreementDataAndKeyWithECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, uiKeyBits, pucResponseID, uiResponseIDLength, pucSponsorID, uiSponsorIDLength, pucSponsorPublicKey, pucSponsorTmpPublicKey,  pucResponsePublicKey,	  pucResponseTmpPublicKey, phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateAgreementDataAndKeyWithECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, uiKeyBits, pucResponseID, uiResponseIDLength, pucSponsorID, uiSponsorIDLength, pucSponsorPublicKey, pucSponsorTmpPublicKey,  pucResponsePublicKey,	  pucResponseTmpPublicKey, phKeyHandle);
#endif
}
//25. 基于 ECC算法的数字信封转换
SGD_RV SDFExchangeDigitEnvelopeBaseOnECC(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,SGD_UINT32  uiAlgID,ECCrefPublicKey *pucPublicKey,ECCCipher *pucEncDataIn,ECCCipher *pucEncDataOut)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UINT32  ,SGD_UINT32  ,ECCrefPublicKey *,ECCCipher *,ECCCipher *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExchangeDigitEnvelopeBaseOnECC");
	return (*fptr)(hSessionHandle,   uiKeyIndex,  uiAlgID, pucPublicKey, pucEncDataIn, pucEncDataOut);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExchangeDigitEnvelopeBaseOnECC");
	return (*fptr)(hSessionHandle,   uiKeyIndex,  uiAlgID, pucPublicKey, pucEncDataIn, pucEncDataOut);
#endif
}
//26. 生成会话密钥并用密钥加密密钥加密输出
SGD_RV SDFGenerateKeyWithKEK(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits,SGD_UINT32  uiAlgID,SGD_UINT32 uiKEKIndex, SGD_UCHAR_PRT *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UINT32 ,SGD_UINT32  ,SGD_UINT32 , SGD_UCHAR *, SGD_UINT32 *, SGD_HANDLE *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateKeyWithKEK");
	return (*fptr)(hSessionHandle,  uiKeyBits,  uiAlgID, uiKEKIndex,  *pucKey,  puiKeyLength,  phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateKeyWithKEK");
	return (*fptr)(hSessionHandle,  uiKeyBits,  uiAlgID, uiKEKIndex,  *pucKey,  puiKeyLength,  phKeyHandle);
#endif
}
//27. 导入会话密钥并用密钥加密密钥解密
SGD_RV SDFImportKeyWithKEK(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiAlgID,SGD_UINT32 uiKEKIndex, SGD_UCHAR_PRT pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UINT32  ,SGD_UINT32 , SGD_UCHAR *, SGD_UINT32 , SGD_HANDLE *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ImportKeyWithKEK");
	return (*fptr)(hSessionHandle,  uiAlgID, uiKEKIndex,  pucKey,  uiKeyLength,  phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ImportKeyWithKEK");
	return (*fptr)(hSessionHandle,  uiAlgID, uiKEKIndex,  pucKey,  uiKeyLength,  phKeyHandle);
#endif
}
//28. 导入明文会话密钥
SGD_RV SDFImportKey(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UCHAR_PRT pucKey, SGD_UINT32 uiKeyLength,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UCHAR *, SGD_UINT32 ,SGD_HANDLE *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ImportKey");
	return (*fptr)(hSessionHandle,  pucKey,  uiKeyLength, phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ImportKey");
	return (*fptr)(hSessionHandle,  pucKey,  uiKeyLength, phKeyHandle);
#endif
}
//29. 销毁会话密钥
SGD_RV SDFDestroyKey(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_HANDLE);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_DestroyKey");
	return (*fptr)(hSessionHandle,  hKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_DestroyKey");
	return (*fptr)(hSessionHandle,  hKeyHandle);
#endif
}

//34. 外部密钥ECC签名
SGD_RV SDFExternalSign_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPrivateKey *pucPrivateKey,SGD_UCHAR_PRT pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32 ,ECCrefPrivateKey *,SGD_UCHAR *,SGD_UINT32  ,ECCSignature *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExternalSign_ECC");
	return (*fptr)(hSessionHandle, uiAlgID, pucPrivateKey, pucData,  uiDataLength, pucSignature);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExternalSign_ECC");
	return (*fptr)(hSessionHandle, uiAlgID, pucPrivateKey, pucData,  uiDataLength, pucSignature);
#endif
}
//35. 外部密钥ECC验证
SGD_RV SDFExternalVerify_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR_PRT pucDataInput,SGD_UINT32  uiInputLength,ECCSignature *pucSignature)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32 ,ECCrefPublicKey *,SGD_UCHAR *,SGD_UINT32  ,ECCSignature *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExternalVerify_ECC");
	return (*fptr)(hSessionHandle, uiAlgID, pucPublicKey, pucDataInput,  uiInputLength, pucSignature);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExternalVerify_ECC");
	return (*fptr)(hSessionHandle, uiAlgID, pucPublicKey, pucDataInput,  uiInputLength, pucSignature);
#endif
}
//36. 内部密钥ECC签名
SGD_RV SDFInternalSign_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UCHAR_PRT pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32  uiISKIndex,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_InternalSign_ECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, pucData,  uiDataLength, pucSignature);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_InternalSign_ECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, pucData,  uiDataLength, pucSignature);
#endif
}
//37. 内部密钥ECC验证
SGD_RV SDFInternalVerify_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UCHAR_PRT pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32  ,ECCSignature *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_InternalVerify_ECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, pucData,  uiDataLength, pucSignature);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_InternalVerify_ECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, pucData,  uiDataLength, pucSignature);
#endif
}
//38. 外部密钥ECC加密
SGD_RV SDFExternalEncrypt_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR_PRT pucData,SGD_UINT32  uiDataLength,ECCCipher *pucEncData)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32 ,ECCrefPublicKey *,SGD_UCHAR *,SGD_UINT32  ,ECCCipher *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExternalEncrypt_ECC");
	return (*fptr)(hSessionHandle, uiAlgID, pucPublicKey, pucData,  uiDataLength, pucEncData);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExternalEncrypt_ECC");
	return (*fptr)(hSessionHandle, uiAlgID, pucPublicKey, pucData,  uiDataLength, pucEncData);
#endif
}
//39. 外部密钥ECC解密
SGD_RV SDFExternalDecrypt_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPrivateKey *pucPrivateKey,ECCCipher *pucEncData,SGD_UCHAR_PRT *pucData,SGD_UINT32  *puiDataLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32 ,ECCrefPrivateKey *,ECCCipher *,SGD_UCHAR *,SGD_UINT32  *);
	*pucData = calloc(*puiDataLength, sizeof(SGD_UCHAR));
	if (*pucData == NULL) {
		return SGD_FALSE;
	}
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExternalDecrypt_ECC");
	return (*fptr)(hSessionHandle, uiAlgID, pucPrivateKey, pucEncData, *pucData,  puiDataLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExternalDecrypt_ECC");
	return (*fptr)(hSessionHandle, uiAlgID, pucPrivateKey, pucEncData, *pucData,  puiDataLength);
#endif
}
//40. 对称加密
SGD_RV SDFEncrypt(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR_PRT pucIV,SGD_UCHAR_PRT pucData,SGD_UINT32 uiDataLength,SGD_UCHAR_PRT *pucEncData,SGD_UINT32  *puiEncDataLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_HANDLE ,SGD_UINT32 ,SGD_UCHAR *,SGD_UCHAR *,SGD_UINT32 ,SGD_UCHAR *,SGD_UINT32  *);
    *pucEncData = calloc(*puiEncDataLength, sizeof(SGD_UCHAR));
	if (*pucEncData == NULL) {
		return SGD_FALSE;
	}
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_Encrypt");
	return (*fptr)(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, *pucEncData,  puiEncDataLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_Encrypt");
	return (*fptr)(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, *pucEncData,  puiEncDataLength);
#endif
}
//41. 对称解密
SGD_RV SDFDecrypt (struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR_PRT pucIV,SGD_UCHAR_PRT pucEncData,SGD_UINT32  uiEncDataLength,SGD_UCHAR_PRT *pucData,SGD_UINT32 *puiDataLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_HANDLE ,SGD_UINT32 ,SGD_UCHAR *,SGD_UCHAR *,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32 *);
    *pucData = calloc(*puiDataLength, sizeof(SGD_UCHAR));
	if (*pucData == NULL) {
		return SGD_FALSE;
	}
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_Decrypt");
	return (*fptr)(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucEncData,  uiEncDataLength, *pucData, puiDataLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_Decrypt");
	return (*fptr)(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucEncData,  uiEncDataLength, *pucData, puiDataLength);
#endif
}
//42. 计算ＭＡＣ
SGD_RV SDFCalculateMAC(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR_PRT pucIV,SGD_UCHAR_PRT pucData,SGD_UINT32 uiDataLength,SGD_UCHAR_PRT *pucMAC,SGD_UINT32  *puiMACLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_HANDLE ,SGD_UINT32 ,SGD_UCHAR *,SGD_UCHAR *,SGD_UINT32 ,SGD_UCHAR *,SGD_UINT32  *);
	*pucMAC = calloc(*puiMACLength, sizeof(SGD_UCHAR));
	if (*pucMAC == NULL) {
		return SGD_FALSE;
	}
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_CalculateMAC");
	return (*fptr)(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, *pucMAC,  puiMACLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_CalculateMAC");
	return (*fptr)(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, *pucMAC,  puiMACLength);
#endif
}
//43. 杂凑运算初始化
SGD_RV SDFHashInit(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR_PRT pucID,SGD_UINT32 uiIDLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32 ,ECCrefPublicKey *,SGD_UCHAR *,SGD_UINT32 );
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_HashInit");
	return (*fptr)(hSessionHandle, uiAlgID, pucPublicKey, pucID, uiIDLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_HashInit");
	return (*fptr)(hSessionHandle, uiAlgID, pucPublicKey, pucID, uiIDLength);
#endif
}
//44. 多包杂凑运算
SGD_RV SDFHashUpdate(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT pucData,SGD_UINT32  uiDataLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UCHAR *,SGD_UINT32  );
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_HashUpdate");
	return (*fptr)(hSessionHandle, pucData,  uiDataLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_HashUpdate");
	return (*fptr)(hSessionHandle, pucData,  uiDataLength);
#endif
}
//45. 杂凑运算结束
SGD_RV SDFHashFinal(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT *pucHash,SGD_UINT32  *puiHashLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UCHAR *,SGD_UINT32  *);
	*pucHash = calloc(*puiHashLength, sizeof(SGD_UCHAR));
	if (*pucHash == NULL) {
		return SGD_FALSE;
	}
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_HashFinal");
	return (*fptr)(hSessionHandle, *pucHash,  puiHashLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_HashFinal");
	return (*fptr)(hSessionHandle, *pucHash,  puiHashLength);
#endif
}


//50. 获取对称句柄
SGD_RV SDFGetSymmKeyHandle(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UINT32 , SGD_HANDLE *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GetSymmKeyHandle");
	return (*fptr)(hSessionHandle,  uiKeyIndex,  phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GetSymmKeyHandle");
	return (*fptr)(hSessionHandle,  uiKeyIndex,  phKeyHandle);
#endif
}
//51. ECC方式的加密
SGD_RV SDFInternalEncrypt_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR_PRT pucData, SGD_UINT32  uiDataLength, ECCCipher *pucEncData)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UINT32  , SGD_UINT32 , SGD_UCHAR *, SGD_UINT32  , ECCCipher *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_InternalEncrypt_ECC");
	return (*fptr)(hSessionHandle,   uiISKIndex,  uiAlgID,  pucData,   uiDataLength,  pucEncData);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_InternalEncrypt_ECC");
	return (*fptr)(hSessionHandle,   uiISKIndex,  uiAlgID,  pucData,   uiDataLength,  pucEncData);
#endif
}
//52. ECC方式的解密
SGD_RV SDFInternalDecrypt_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UINT32 uiAlgID,ECCCipher *pucEncData,SGD_UCHAR_PRT *pucData,SGD_UINT32  *puiDataLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32  ,SGD_UINT32 ,ECCCipher *,SGD_UCHAR *,SGD_UINT32  *);
	*pucData = calloc(*puiDataLength, sizeof(SGD_UCHAR));
	if (*pucData == NULL) {
		return SGD_FALSE;
	}
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_InternalDecrypt_ECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, uiAlgID, pucEncData, *pucData,  puiDataLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_InternalDecrypt_ECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, uiAlgID, pucEncData, *pucData,  puiDataLength);
#endif
}

//54. EPK方式导出ECC密钥
SGD_RV SDFExportKeyWithEPK_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_HANDLE , SGD_UINT32 , ECCrefPublicKey *, ECCCipher *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExportKeyWithEPK_ECC");
	return (*fptr)(hSessionHandle,  hKeyHandle,  uiAlgID,  pucPublicKey,  pucKey);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExportKeyWithEPK_ECC");
	return (*fptr)(hSessionHandle,  hKeyHandle,  uiAlgID,  pucPublicKey,  pucKey);
#endif
}
//55. EPK方式导出密钥
SGD_RV SDFExportKeyWithKEK(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiKEKIndex, SGD_UCHAR_PRT *pucKey, SGD_UINT32 *puiKeyLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_HANDLE , SGD_UINT32 , SGD_UINT32 , SGD_UCHAR *, SGD_UINT32 *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExportKeyWithKEK");
	return (*fptr)(hSessionHandle,  hKeyHandle,  uiAlgID,  uiKEKIndex,  *pucKey,  puiKeyLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExportKeyWithKEK");
	return (*fptr)(hSessionHandle,  hKeyHandle,  uiAlgID,  uiKEKIndex,  *pucKey,  puiKeyLength);
#endif
}
*/
import "C"
import (
	"fmt"
	"os"
	"strings"
	"unsafe"
)

func ConvertToDeviceInfoGo(deviceInfo1 C.DEVICEINFO) (deviceInfo DeviceInfo) {
	deviceInfo = DeviceInfo{
		IssuerName:      strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&deviceInfo1.IssuerName[0]), 40)), " "),
		DeviceName:      strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&deviceInfo1.DeviceName[0]), 16)), " "),
		DeviceSerial:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&deviceInfo1.DeviceSerial[0]), 16)), " "),
		DeviceVersion:   uint(deviceInfo1.DeviceVersion),
		StandardVersion: uint(deviceInfo1.StandardVersion),
		SymAlgAbility:   uint(deviceInfo1.SymAlgAbility),
		HashAlgAbility:  uint(deviceInfo1.HashAlgAbility),
		BufferSize:      uint(deviceInfo1.BufferSize),
	}
	temp1 := C.GoBytes(unsafe.Pointer(&deviceInfo1.AsymAlgAbility[0]), 2)
	temp2 := C.GoBytes(unsafe.Pointer(&deviceInfo1.AsymAlgAbility[1]), 2)
	deviceInfo.AsymAlgAbility[0] = uint(temp1[0])
	deviceInfo.AsymAlgAbility[1] = uint(temp2[0])
	return deviceInfo
}

func ConvertToRSArefPrivateKeyC(privateKey RSArefPrivateKey) (pucPrivateKey C.RSArefPrivateKey) {
	pucPrivateKey.bits = C.SGD_UINT32(privateKey.Bits)
	for i := 0; i < len(privateKey.M); i++ {
		pucPrivateKey.m[i] = C.SGD_UCHAR(privateKey.M[i])
	}
	for i := 0; i < len(privateKey.E); i++ {
		pucPrivateKey.e[i] = C.SGD_UCHAR(privateKey.E[i])
	}
	for i := 0; i < len(privateKey.D); i++ {
		pucPrivateKey.d[i] = C.SGD_UCHAR(privateKey.D[i])
	}
	for i := 0; i < len(privateKey.Coef); i++ {
		pucPrivateKey.coef[i] = C.SGD_UCHAR(privateKey.Coef[i])
	}

	for i := 0; i < len(privateKey.Prime[0]); i++ {
		pucPrivateKey.prime[0][i] = C.SGD_UCHAR(privateKey.Prime[0][i])
	}
	for i := 0; i < len(privateKey.Prime[0]); i++ {
		pucPrivateKey.prime[1][i] = C.SGD_UCHAR(privateKey.Prime[1][i])
	}

	for i := 0; i < len(privateKey.Pexp[0]); i++ {
		pucPrivateKey.pexp[0][i] = C.SGD_UCHAR(privateKey.Pexp[0][i])
	}
	for i := 0; i < len(privateKey.Pexp[0]); i++ {
		pucPrivateKey.pexp[1][i] = C.SGD_UCHAR(privateKey.Pexp[1][i])
	}
	return pucPrivateKey
}

func ConvertToRSArefPrivateKeyGo(pucPrivateKey C.RSArefPrivateKey) (privateKey RSArefPrivateKey) {
	privateKey = RSArefPrivateKey{
		Bits: uint(pucPrivateKey.bits),
		M:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.m[0]), 256)), " "),
		E:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.e[0]), 256)), " "),
		D:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.d[0]), 256)), " "),
		Coef: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.coef[0]), 128)), " "),
	}
	privateKey.Prime[0] = strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.prime[0]), 128)), " ")
	privateKey.Prime[1] = strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.prime[1]), 128)), " ")
	privateKey.Pexp[0] = strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.pexp[0]), 128)), " ")
	privateKey.Pexp[1] = strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.pexp[1]), 128)), " ")
	return privateKey
}

func ConvertToRSArefPublicKeyC(publicKey RSArefPublicKey) (pucPublicKey C.RSArefPublicKey) {
	pucPublicKey.bits = C.SGD_UINT32(publicKey.Bits)
	for i := 0; i < len(publicKey.M); i++ {
		pucPublicKey.m[i] = C.SGD_UCHAR(publicKey.M[i])
	}
	for i := 0; i < len(publicKey.E); i++ {
		pucPublicKey.e[i] = C.SGD_UCHAR(publicKey.E[i])
	}
	return pucPublicKey
}

func ConvertToRSArefPublicKeyGo(pucPublicKey C.RSArefPublicKey) (publicKey RSArefPublicKey) {
	publicKey = RSArefPublicKey{
		Bits: uint(pucPublicKey.bits),
		M:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.m[0]), 256)), " "),
		E:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.e[0]), 256)), " "),
	}
	return publicKey
}

func ConvertToECCrefPublicKeyC(publicKey ECCrefPublicKey) (pucPublicKey C.ECCrefPublicKey) {

	pucPublicKey.bits = C.SGD_UINT32(publicKey.Bits)
	for i := 0; i < len(publicKey.X); i++ {
		pucPublicKey.x[i] = C.SGD_UCHAR(publicKey.X[i])
	}
	for i := 0; i < len(publicKey.Y); i++ {
		pucPublicKey.y[i] = C.SGD_UCHAR(publicKey.Y[i])
	}
	return pucPublicKey
}

func ConvertToECCrefPublicKeyGo(pucPublicKey C.ECCrefPublicKey) (publicKey ECCrefPublicKey) {
	publicKey = ECCrefPublicKey{
		Bits: uint(pucPublicKey.bits),
		X:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.x[0]), 64)), " "),
		Y:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.y[0]), 64)), " "),
	}
	return publicKey
}

func ConvertToECCrefPrivateKeyC(privateKey ECCrefPrivateKey) (pucPrivateKey C.ECCrefPrivateKey) {
	pucPrivateKey.bits = C.SGD_UINT32(privateKey.Bits)
	for i := 0; i < len(privateKey.K); i++ {
		pucPrivateKey.K[i] = C.SGD_UCHAR(privateKey.K[i])
	}
	return pucPrivateKey
}

func ConvertToECCrefPrivateKeyGo(pucPrivateKey C.ECCrefPrivateKey) (privateKey ECCrefPrivateKey) {
	privateKey = ECCrefPrivateKey{
		Bits: uint(pucPrivateKey.bits),
		K:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.K[0]), 32)), " "),
	}
	return privateKey
}

func ConvertToECCCipherC(encData ECCCipher) (pucEncData C.ECCCipher) {
	for i := 0; i < len(encData.X); i++ {
		pucEncData.x[i] = C.SGD_UCHAR(encData.X[i])
	}
	for i := 0; i < len(encData.Y); i++ {
		pucEncData.y[i] = C.SGD_UCHAR(encData.Y[i])
	}
	for i := 0; i < len(encData.M); i++ {
		pucEncData.M[i] = C.SGD_UCHAR(encData.M[i])
	}
	pucEncData.L = C.SGD_UINT32(encData.L)
	for i := 0; i < len(encData.C); i++ {
		pucEncData.C[i] = C.SGD_UCHAR(encData.C[i])
	}
	return pucEncData
}
func ConvertToECCCipherGo(pucKey C.ECCCipher) (key ECCCipher) {
	key = ECCCipher{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.x[0]), 64)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.y[0]), 64)), " "),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.M[0]), 32)), " "),
		L: uint(pucKey.L),
		C: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.C[0]), C.int(pucKey.L))), " "),
	}
	return key
}

func ConvertToECCSignatureC(signature ECCSignature) (pSignature C.ECCSignature) {
	for i := 0; i < len(signature.R); i++ {
		pSignature.r[i] = C.SGD_UCHAR(signature.R[i])
	}
	for i := 0; i < len(signature.S); i++ {
		pSignature.s[i] = C.SGD_UCHAR(signature.S[i])
	}
	return pSignature
}

func ConvertToECCSignatureGo(pucSignature C.ECCSignature) (signature ECCSignature) {
	signature = ECCSignature{
		R: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSignature.r[0]), 64)), " "),
		S: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSignature.s[0]), 64)), " "),
	}
	return signature
}

func New(libPath string) *Ctx {
	if x := os.Getenv("SDFHSM_CONF"); x == "" {
		os.Setenv("SDFHSM_CONF", libPath)
	} else {
		libPath = x
	}
	c := new(Ctx)
	mod := C.CString(libPath)
	defer C.free(unsafe.Pointer(mod))
	c.libHandle = C.New(mod)
	if c.libHandle == nil {
		return nil
	}
	return c
}

func ToError(e C.SGD_RV) error {
	if e == C.SDR_OK {
		return nil
	}
	err_code := uint(e)
	str := fmt.Sprintf("sdf: 0x%X:%s", err_code, StrErrors[err_code])
	return fmt.Errorf(str)
}

func deepCopy(src []byte) (dst []byte) {
	dst = make([]byte, len(src))
	for i, v := range src {
		dst[i] = v
	}
	return
}

func (c *Ctx) Destroy() {
	if c == nil || c.libHandle == nil {
		return
	}
	C.Destroy(c.libHandle)
	c.libHandle = nil
}

type Ctx struct {
	libHandle *C.struct_LibHandle
}

type DeviceHandleType C.SGD_HANDLE
type SessionHandleType C.SGD_HANDLE
type KeyHandleType C.SGD_HANDLE
type AgreementHandleType C.SGD_HANDLE

var stubData = []byte{0}

func CMessage(data []byte) (dataPtr C.SGD_UCHAR_PRT) {
	l := len(data)
	if l == 0 {
		data = stubData
	}
	dataPtr = C.SGD_UCHAR_PRT(unsafe.Pointer(&data[0]))
	return dataPtr
}

// SDFOpenDevice 1.打开设备
func (c *Ctx) SDFOpenDevice() (deviceHandle DeviceHandleType, err error) {
	var err1 C.SGD_RV
	var dH C.SGD_HANDLE
	err1 = C.SDFOpenDevice(c.libHandle, &dH)
	err = ToError(err1)
	deviceHandle = DeviceHandleType(dH)
	return deviceHandle, err
}

// SDFCloseDevice 2.关闭设备
func (c *Ctx) SDFCloseDevice(deviceHandle DeviceHandleType) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFCloseDevice(c.libHandle, C.SGD_HANDLE(deviceHandle))
	return ToError(err1)
}

// SDFOpenSession 3.创建会话
func (c *Ctx) SDFOpenSession(deviceHandle DeviceHandleType) (sessionHandle SessionHandleType, err error) {
	var err1 C.SGD_RV
	var s C.SGD_HANDLE
	err1 = C.SDFOpenSession(c.libHandle, C.SGD_HANDLE(deviceHandle), &s)
	sessionHandle = SessionHandleType(s)
	return sessionHandle, ToError(err1)
}

// SDFCloseSession 4.关闭会话
func (c *Ctx) SDFCloseSession(sessionHandle SessionHandleType) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFCloseSession(c.libHandle, C.SGD_HANDLE(sessionHandle))
	return ToError(err1)
}

// SDFGetDeviceInfo 5.获取设备信息
func (c *Ctx) SDFGetDeviceInfo(sessionHandle SessionHandleType) (deviceInfo DeviceInfo, err error) {
	var deviceInfo1 C.DEVICEINFO
	var err1 C.SGD_RV
	err1 = C.SDFGetDeviceInfo(c.libHandle, C.SGD_HANDLE(sessionHandle), &deviceInfo1)
	deviceInfo = ConvertToDeviceInfoGo(deviceInfo1)
	err = ToError(err1)
	return deviceInfo, err
}

// SDFGenerateRandom 6.产生随机数
func (c *Ctx) SDFGenerateRandom(sessionHandle SessionHandleType, length uint) (randomData []byte, err error) {
	var err1 C.SGD_RV
	var random C.SGD_UCHAR_PRT
	err1 = C.SDFGenerateRandom(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(length), &random)
	err = ToError(err1)
	randomData = C.GoBytes(unsafe.Pointer(random), C.int(length))
	C.free(unsafe.Pointer(random))
	return randomData, err
}

// SDFGetPrivateKeyAccessRight 7.获取私钥使用权限
func (c *Ctx) SDFGetPrivateKeyAccessRight(sessionHandle SessionHandleType, keyIndex uint, password []byte, pwdLength uint) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFGetPrivateKeyAccessRight(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyIndex), CMessage(password), C.SGD_UINT32(pwdLength))
	err = ToError(err1)
	return err
}

// SDFReleasePrivateKeyAccessRight 8.释放私钥使用权限
func (c *Ctx) SDFReleasePrivateKeyAccessRight(sessionHandle SessionHandleType, keyIndex uint) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFReleasePrivateKeyAccessRight(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyIndex))
	err = ToError(err1)
	return err
}

// SDFExportSignPublicKey_RSA 9.导出 RSA 签名公钥
func (c *Ctx) SDFExportSignPublicKey_RSA(sessionHandle SessionHandleType, keyIndex uint) (publicKey RSArefPublicKey, err error) {
	var err1 C.SGD_RV
	var pucPublicKey C.RSArefPublicKey
	err1 = C.SDFExportSignPublicKey_RSA(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyIndex), &pucPublicKey)
	publicKey = ConvertToRSArefPublicKeyGo(pucPublicKey)
	err = ToError(err1)
	return publicKey, err
}

// SDFExportEncPublicKey_RSA 10.导出 RSA 加密公钥
func (c *Ctx) SDFExportEncPublicKey_RSA(sessionHandle SessionHandleType, keyIndex uint) (publicKey RSArefPublicKey, err error) {
	var err1 C.SGD_RV
	var pucPublicKey C.RSArefPublicKey
	err1 = C.SDFExportEncPublicKey_RSA(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyIndex), &pucPublicKey)
	publicKey = ConvertToRSArefPublicKeyGo(pucPublicKey)
	err = ToError(err1)
	return publicKey, err
}

// SDFGenerateKeyPair_RSA 11.产生 RSA 非对称密钥对并输出
func (c *Ctx) SDFGenerateKeyPair_RSA(sessionHandle SessionHandleType, uiKeyBits uint) (publicKey RSArefPublicKey, privateKey RSArefPrivateKey, err error) {

	var err1 C.SGD_RV
	var pucPublicKey C.RSArefPublicKey
	var pucPrivateKey C.RSArefPrivateKey
	err1 = C.SDFGenerateKeyPair_RSA(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyBits), &pucPublicKey, &pucPrivateKey)
	publicKey = ConvertToRSArefPublicKeyGo(pucPublicKey)
	privateKey = ConvertToRSArefPrivateKeyGo(pucPrivateKey)
	err = ToError(err1)
	return publicKey, privateKey, err
}

// SDFGenerateKeyWithIPK_RSA 12.生成会话密钥并用内部 RSA 公钥加密输出
func (c *Ctx) SDFGenerateKeyWithIPK_RSA(sessionHandle SessionHandleType, uiIPKIndex uint, uiKeyBits uint) (key []byte, keyLength uint, keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var pucKey C.SGD_UCHAR_PRT
	var length C.SGD_UINT32
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFGenerateKeyWithIPK_RSA(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiIPKIndex), C.SGD_UINT32(uiKeyBits), &pucKey, &length, &phKeyHandle)
	key = C.GoBytes(unsafe.Pointer(pucKey), C.int(length))
	C.free(unsafe.Pointer(pucKey))
	keyLength = uint(length)
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return key, keyLength, keyHandle, err
}

// SDFGenerateKeyWithEPK_RSA 13.生成会话密钥并用外部 RSA 公钥加密输出
func (c *Ctx) SDFGenerateKeyWithEPK_RSA(sessionHandle SessionHandleType, uiKeyBits uint, publicKey RSArefPublicKey) (key []byte, keyLength uint, keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var pucKey C.SGD_UCHAR_PRT
	var puiKeyLength C.SGD_UINT32
	var phKeyHandle C.SGD_HANDLE
	pubKey := ConvertToRSArefPublicKeyC(publicKey)
	err1 = C.SDFGenerateKeyWithEPK_RSA(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyBits), &pubKey, &pucKey, &puiKeyLength, &phKeyHandle)
	key = C.GoBytes(unsafe.Pointer(pucKey), C.int(puiKeyLength))
	keyLength = uint(puiKeyLength)
	C.free(unsafe.Pointer(pucKey))
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return key, keyLength, keyHandle, err
}

// SDFImportKeyWithISK_RSA 14.导入会话密钥并用内部 RSA 私钥解密
func (c *Ctx) SDFImportKeyWithISK_RSA(sessionHandle SessionHandleType, uiKeyBits uint, key []byte, uiKeyLength uint) (keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFImportKeyWithISK_RSA(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyBits), CMessage(key), C.SGD_UINT32(uiKeyLength), &phKeyHandle)
	err = ToError(err1)
	keyHandle = KeyHandleType(phKeyHandle)
	return keyHandle, err
}

// SDFExchangeDigitEnvelopeBaseOnRSA 15.基于 RSA 算法的数字信封转换
func (c *Ctx) SDFExchangeDigitEnvelopeBaseOnRSA(sessionHandle SessionHandleType, keyIndex uint, publicKey RSArefPublicKey, deInput []byte, deLength uint) (deOutput []byte, deOutputLength uint, err error) {
	var err1 C.SGD_RV
	var pucDEOutput C.SGD_UCHAR_PRT
	var puiDELength C.SGD_UINT32
	pucPublicKey := ConvertToRSArefPublicKeyC(publicKey)
	err1 = C.SDFExchangeDigitEnvelopeBaseOnRSA(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyIndex), &pucPublicKey, CMessage(deInput), C.SGD_UINT32(deLength), &pucDEOutput, &puiDELength)
	deOutput = C.GoBytes(unsafe.Pointer(pucDEOutput), C.int(puiDELength))
	C.free(unsafe.Pointer(pucDEOutput))
	deOutputLength = uint(puiDELength)
	err = ToError(err1)
	return deOutput, deOutputLength, err
}

// SDFExportSignPublicKey_ECC 16.导出 ECC签名公钥
func (c *Ctx) SDFExportSignPublicKey_ECC(sessionHandle SessionHandleType, uiKeyIndex uint) (publicKey ECCrefPublicKey, err error) {
	var err1 C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	err1 = C.SDFExportSignPublicKey_ECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyIndex), &pucPublicKey)
	publicKey = ConvertToECCrefPublicKeyGo(pucPublicKey)
	err = ToError(err1)
	return publicKey, err
}

// SDFExportEncPublicKey_ECC 17.导出 ECC加密公钥
func (c *Ctx) SDFExportEncPublicKey_ECC(sessionHandle SessionHandleType, uiKeyIndex uint) (publicKey ECCrefPublicKey, err error) {
	var err1 C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	err1 = C.SDFExportEncPublicKey_ECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyIndex), &pucPublicKey)
	publicKey = ConvertToECCrefPublicKeyGo(pucPublicKey)
	err = ToError(err1)
	return publicKey, err
}

// SDFGenerateKeyPair_ECC 18.产生 ECC非对称密钥对并输出
func (c *Ctx) SDFGenerateKeyPair_ECC(sessionHandle SessionHandleType, uiAlgID uint, uiKeyBits uint) (publicKey ECCrefPublicKey, privateKey ECCrefPrivateKey, err error) {
	var err1 C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	var pucPrivateKey C.ECCrefPrivateKey
	err1 = C.SDFGenerateKeyPair_ECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiAlgID), C.SGD_UINT32(uiKeyBits), &pucPublicKey, &pucPrivateKey)
	publicKey = ConvertToECCrefPublicKeyGo(pucPublicKey)
	privateKey = ConvertToECCrefPrivateKeyGo(pucPrivateKey)
	err = ToError(err1)
	return publicKey, privateKey, err
}

// SDFGenerateKeyWithIPK_ECC 19.生成会话密钥并用内部 ECC公钥加密输出
func (c *Ctx) SDFGenerateKeyWithIPK_ECC(sessionHandle SessionHandleType, uiIPKIndex uint, uiKeyBits uint) (key ECCCipher, keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var pucKey C.ECCCipher
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFGenerateKeyWithIPK_ECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiIPKIndex), C.SGD_UINT32(uiKeyBits), &pucKey, &phKeyHandle)
	key = ConvertToECCCipherGo(pucKey)
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return key, keyHandle, err
}

// SDFGenerateKeyWithEPK_ECC 20.生成会话密钥并用外部 ECC公钥加密输出
func (c *Ctx) SDFGenerateKeyWithEPK_ECC(sessionHandle SessionHandleType, uiKeyBits uint, uiAlgID uint, publicKey ECCrefPublicKey) (key ECCCipher, keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	pucPublicKey.bits = C.SGD_UINT32(publicKey.Bits)
	for i := 0; i < len(publicKey.X); i++ {
		pucPublicKey.x[i] = C.SGD_UCHAR(publicKey.Y[i])
	}
	for i := 0; i < len(publicKey.Y); i++ {
		pucPublicKey.y[i] = C.SGD_UCHAR(publicKey.Y[i])
	}
	var pucKey C.ECCCipher
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFGenerateKeyWithEPK_ECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyBits), C.SGD_UINT32(uiAlgID), &pucPublicKey, &pucKey, &phKeyHandle)
	key = ConvertToECCCipherGo(pucKey)
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return key, keyHandle, err
}

// SDFImportKeyWithISK_ECC 21.导入会话密钥并用内部 ECC私钥解密
func (c *Ctx) SDFImportKeyWithISK_ECC(sessionHandle SessionHandleType, uiISKIndex uint, key ECCCipher) (keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var phKeyHandle C.SGD_HANDLE
	pucKey := ConvertToECCCipherC(key)
	err1 = C.SDFImportKeyWithISK_ECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiISKIndex), &pucKey, &phKeyHandle)
	err = ToError(err1)
	keyHandle = KeyHandleType(phKeyHandle)
	return keyHandle, err
}

// SDFGenerateAgreementDataWithECC 22.生成密钥协商参数并输出
func (c *Ctx) SDFGenerateAgreementDataWithECC(sessionHandle SessionHandleType, uiISKIndex uint, uiKeyBits uint, sponsorID []byte, sponsorIDLength uint) (sponsorPublicKey ECCrefPublicKey, sponsorTmpPublicKey ECCrefPublicKey, agreementHandle AgreementHandleType, err error) {
	var err1 C.SGD_RV
	var pucSponsorPublicKey C.ECCrefPublicKey
	var pucSponsorTmpPublicKey C.ECCrefPublicKey
	var phAgreementHandle C.SGD_HANDLE
	err1 = C.SDFGenerateAgreementDataWithECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiISKIndex), C.SGD_UINT32(uiKeyBits), CMessage(sponsorID), C.SGD_UINT32(sponsorIDLength), &pucSponsorPublicKey, &pucSponsorTmpPublicKey, &phAgreementHandle)
	sponsorPublicKey = ConvertToECCrefPublicKeyGo(pucSponsorPublicKey)
	sponsorTmpPublicKey = ConvertToECCrefPublicKeyGo(pucSponsorTmpPublicKey)
	agreementHandle = AgreementHandleType(phAgreementHandle)
	err = ToError(err1)
	return sponsorPublicKey, sponsorTmpPublicKey, agreementHandle, err
}

// SDFGenerateKeyWithECC 23.计算会话密钥
func (c *Ctx) SDFGenerateKeyWithECC(sessionHandle SessionHandleType, responseID []byte, responseIDLength uint, responsePublicKey ECCrefPublicKey, responseTmpPublicKey ECCrefPublicKey, hAgreementHandle AgreementHandleType) (keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	pucResponsePublicKey := ConvertToECCrefPublicKeyC(responsePublicKey)
	pucResponseTmpPublicKey := ConvertToECCrefPublicKeyC(responseTmpPublicKey)
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFGenerateKeyWithECC(c.libHandle, C.SGD_HANDLE(sessionHandle), CMessage(responseID), C.SGD_UINT32(responseIDLength), &pucResponsePublicKey, &pucResponseTmpPublicKey, C.SGD_HANDLE(hAgreementHandle), &phKeyHandle)
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return keyHandle, err
}

// SDFGenerateAgreementDataAndKeyWithECC 24.产生协商数据并计算会话密钥
func (c *Ctx) SDFGenerateAgreementDataAndKeyWithECC(sessionHandle SessionHandleType, uiISKIndex uint, uiKeyBits uint, responseID []byte, responseIDLength uint, sponsorID []byte, sponsorIDLength uint, sponsorPublicKey ECCrefPublicKey, sponsorTmpPublicKey ECCrefPublicKey) (responsePublicKey ECCrefPublicKey, responseTmpPublicKey ECCrefPublicKey, keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	pucSponsorPublicKey := ConvertToECCrefPublicKeyC(sponsorPublicKey)
	pucSponsorTmpPublicKey := ConvertToECCrefPublicKeyC(sponsorTmpPublicKey)
	var pucResponsePublicKey C.ECCrefPublicKey
	var pucResponseTmpPublicKey C.ECCrefPublicKey
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFGenerateAgreementDataAndKeyWithECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiISKIndex), C.SGD_UINT32(uiKeyBits), CMessage(responseID), C.SGD_UINT32(responseIDLength), CMessage(sponsorID), C.SGD_UINT32(sponsorIDLength), &pucSponsorPublicKey, &pucSponsorTmpPublicKey, &pucResponsePublicKey, &pucResponseTmpPublicKey, &phKeyHandle)
	responsePublicKey = ConvertToECCrefPublicKeyGo(pucResponsePublicKey)
	responseTmpPublicKey = ConvertToECCrefPublicKeyGo(pucResponseTmpPublicKey)
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return responsePublicKey, responseTmpPublicKey, keyHandle, err
}

// SDFExchangeDigitEnvelopeBaseOnECC 25.基于 ECC算法的数字信封转换
func (c *Ctx) SDFExchangeDigitEnvelopeBaseOnECC(sessionHandle SessionHandleType, uiKeyIndex uint, uiAlgID uint, publicKey ECCrefPublicKey, encDataIn ECCCipher) (encDataOut ECCCipher, err error) {
	var err1 C.SGD_RV
	var pucEncDataOut C.ECCCipher
	pucPublicKey := ConvertToECCrefPublicKeyC(publicKey)
	pucEncDataIn := ConvertToECCCipherC(encDataIn)
	err1 = C.SDFExchangeDigitEnvelopeBaseOnECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyIndex), C.SGD_UINT32(uiAlgID), &pucPublicKey, &pucEncDataIn, &pucEncDataOut)
	encDataOut = ConvertToECCCipherGo(pucEncDataOut)
	err = ToError(err1)
	return encDataOut, err
}

// SDFGenerateKeyWithKEK 26.生成会话密钥并用密钥加密密钥加密输出
func (c *Ctx) SDFGenerateKeyWithKEK(sessionHandle SessionHandleType, uiKeyBits uint, uiAlgID uint, uiKEKIndex uint) ([]byte, uint, KeyHandleType, error) {
	var err C.SGD_RV
	var pucKey C.SGD_UCHAR_PRT
	var keyLength C.SGD_UINT32
	var phKeyHandle C.SGD_HANDLE
	err = C.SDFGenerateKeyWithKEK(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyBits), C.SGD_UINT32(uiAlgID), C.SGD_UINT32(uiKEKIndex), &pucKey, &keyLength, &phKeyHandle)
	p := C.GoBytes(unsafe.Pointer(pucKey), C.int(keyLength))
	C.free(unsafe.Pointer(pucKey))
	return p, uint(keyLength), KeyHandleType(phKeyHandle), ToError(err)
}

// SDFImportKeyWithKEK 27.导入会话密钥并用密钥加密密钥解密
func (c *Ctx) SDFImportKeyWithKEK(sessionHandle SessionHandleType, uiAlgID uint, uiKEKIndex uint, key []byte, uiKeyLength uint) (keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFImportKeyWithKEK(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiAlgID), C.SGD_UINT32(uiKEKIndex), CMessage(key), C.SGD_UINT32(uiKeyLength), &phKeyHandle)
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return keyHandle, err
}

// SDFImportKey 28.导入明文会话密钥
func (c *Ctx) SDFImportKey(sessionHandle SessionHandleType, pucKey []byte, uiKeyLength uint) (keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFImportKey(c.libHandle, C.SGD_HANDLE(sessionHandle), CMessage(pucKey), C.SGD_UINT32(uiKeyLength), &phKeyHandle)
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return keyHandle, err
}

// SDFDestroyKey 29.销毁会话密钥
func (c *Ctx) SDFDestroyKey(sessionHandle SessionHandleType, hKeyHandle KeyHandleType) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFDestroyKey(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_HANDLE(hKeyHandle))
	err = ToError(err1)
	return err
}

// SDFExternalSign_ECC 34. 外部密钥ECC签名
func (c *Ctx) SDFExternalSign_ECC(sessionHandle SessionHandleType, uiAlgID uint, privateKey ECCrefPrivateKey, pucData []byte, uiDataLength uint) (signature ECCSignature, err error) {
	var err1 C.SGD_RV
	pucPrivateKey := ConvertToECCrefPrivateKeyC(privateKey)
	var pucSignature C.ECCSignature
	err1 = C.SDFExternalSign_ECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiAlgID), &pucPrivateKey, CMessage(pucData), C.SGD_UINT32(uiDataLength), &pucSignature)
	signature = ConvertToECCSignatureGo(pucSignature)
	err = ToError(err1)
	return signature, err
}

// SDFExternalVerify_ECC 35.外部密钥 ECC验证
func (c *Ctx) SDFExternalVerify_ECC(sessionHandle SessionHandleType, uiAlgID uint, publicKey ECCrefPublicKey, inputData []byte, uiInputLength uint, signature ECCSignature) (err error) {
	var err1 C.SGD_RV
	pucPublicKey := ConvertToECCrefPublicKeyC(publicKey)
	pucSignature := ConvertToECCSignatureC(signature)
	err1 = C.SDFExternalVerify_ECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiAlgID), &pucPublicKey, CMessage(inputData), C.SGD_UINT32(uiInputLength), &pucSignature)
	err = ToError(err1)
	return err
}

// SDFInternalSign_ECC 36.内部密钥 ECC签名
func (c *Ctx) SDFInternalSign_ECC(sessionHandle SessionHandleType, uiISKIndex uint, pucData []byte, uiDataLength uint) (signature ECCSignature, err error) {
	var err1 C.SGD_RV
	var pucSignature C.ECCSignature
	err1 = C.SDFInternalSign_ECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiISKIndex), CMessage(pucData), C.SGD_UINT32(uiDataLength), &pucSignature)
	signature = ConvertToECCSignatureGo(pucSignature)
	err = ToError(err1)
	return signature, err
}

// SDFInternalVerify_ECC 37.内部密钥 ECC验证
func (c *Ctx) SDFInternalVerify_ECC(sessionHandle SessionHandleType, uiISKIndex uint, pucData []byte, uiDataLength uint, signature ECCSignature) (err error) {
	var err1 C.SGD_RV
	var pucSignature C.ECCSignature
	for i := 0; i < len(signature.R); i++ {
		pucSignature.r[i] = C.SGD_UCHAR(signature.R[i])
	}
	for i := 0; i < len(signature.S); i++ {
		pucSignature.s[i] = C.SGD_UCHAR(signature.S[i])
	}
	err1 = C.SDFInternalVerify_ECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiISKIndex), CMessage(pucData), C.SGD_UINT32(uiDataLength), &pucSignature)
	err = ToError(err1)
	return err
}

// SDFExternalEncrypt_ECC 38.外部密钥 ECC加密
func (c *Ctx) SDFExternalEncrypt_ECC(sessionHandle SessionHandleType, uiAlgID uint, publicKey ECCrefPublicKey, data []byte, dataLength uint) (encData ECCCipher, err error) {
	var err1 C.SGD_RV
	pucPublicKey := ConvertToECCrefPublicKeyC(publicKey)
	var pucEncData C.ECCCipher
	err1 = C.SDFExternalEncrypt_ECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiAlgID), &pucPublicKey, CMessage(data), C.SGD_UINT32(dataLength), &pucEncData)
	encData = ConvertToECCCipherGo(pucEncData)
	err = ToError(err1)
	return encData, err
}

// SDFExternalDecrypt_ECC 39.外部密钥 ECC解密
func (c *Ctx) SDFExternalDecrypt_ECC(sessionHandle SessionHandleType, uiAlgID uint, privateKey ECCrefPrivateKey, encData ECCCipher) (data []byte, dataLength uint, err error) {
	var err1 C.SGD_RV
	pucPrivateKey := ConvertToECCrefPrivateKeyC(privateKey)
	pucEncData := ConvertToECCCipherC(encData)
	var pucData C.SGD_UCHAR_PRT
	var puiDataLength C.SGD_UINT32
	err1 = C.SDFExternalDecrypt_ECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiAlgID), &pucPrivateKey, &pucEncData, &pucData, &puiDataLength)
	data = C.GoBytes(unsafe.Pointer(pucData), C.int(puiDataLength))
	dataLength = uint(puiDataLength)
	C.free(unsafe.Pointer(pucData))
	err = ToError(err1)
	return data, dataLength, err
}

// SDFEncrypt 40.对称加密
func (c *Ctx) SDFEncrypt(sessionHandle SessionHandleType, keyHandle KeyHandleType, algID uint, iv []byte, data []byte, dataLength uint) (encData []byte, encDataLength uint, err error) {
	var err1 C.SGD_RV
	var pucEncData C.SGD_UCHAR_PRT
	var puiEncDataLength C.SGD_UINT32
	err1 = C.SDFEncrypt(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_HANDLE(keyHandle), C.SGD_UINT32(algID), CMessage(iv), CMessage(data), C.SGD_UINT32(dataLength), &pucEncData, &puiEncDataLength)
	encData = C.GoBytes(unsafe.Pointer(pucEncData), C.int(puiEncDataLength))
	encDataLength = uint(puiEncDataLength)
	err = ToError(err1)
	C.free(unsafe.Pointer(pucEncData))
	return encData, uint(puiEncDataLength), err
}

// SDFDecrypt 41.对称解密
func (c *Ctx) SDFDecrypt(sessionHandle SessionHandleType, hKeyHandle KeyHandleType, uiAlgID uint, iv []byte, encData []byte, encDataLength uint) (data []byte, dataLength uint, err error) {
	var err1 C.SGD_RV
	var pucData C.SGD_UCHAR_PRT
	var puiDataLength C.SGD_UINT32
	err1 = C.SDFDecrypt(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_HANDLE(hKeyHandle), C.SGD_UINT32(uiAlgID), CMessage(iv), CMessage(encData), C.SGD_UINT32(encDataLength), &pucData, &puiDataLength)
	data = C.GoBytes(unsafe.Pointer(pucData), C.int(puiDataLength))
	dataLength = uint(puiDataLength)
	C.free(unsafe.Pointer(pucData))
	err = ToError(err1)
	return data, dataLength, err
}

// SDFCalculateMAC 42.计算 MAC
func (c *Ctx) SDFCalculateMAC(sessionHandle SessionHandleType, hKeyHandle KeyHandleType, uiAlgID uint, iv []byte, data []byte, dataLength uint) (mac []byte, macLength uint, err error) {
	var err1 C.SGD_RV
	var pucMAC C.SGD_UCHAR_PRT
	var puiMACLength C.SGD_UINT32
	err1 = C.SDFCalculateMAC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_HANDLE(hKeyHandle), C.SGD_UINT32(uiAlgID), CMessage(iv), CMessage(data), C.SGD_UINT32(dataLength), &pucMAC, &puiMACLength)
	mac = C.GoBytes(unsafe.Pointer(pucMAC), C.int(puiMACLength))
	macLength = uint(puiMACLength)
	C.free(unsafe.Pointer(pucMAC))
	err = ToError(err1)
	return mac, macLength, err
}

// SDFHashInit 43.杂凑运算初始化
func (c *Ctx) SDFHashInit(sessionHandle SessionHandleType, uiAlgID uint, pucID []byte, uiIDLength uint) (publicKey ECCrefPublicKey, err error) {
	var err1 C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	err1 = C.SDFHashInit(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiAlgID), &pucPublicKey, CMessage(pucID), C.SGD_UINT32(uiIDLength))
	publicKey = ConvertToECCrefPublicKeyGo(pucPublicKey)
	err = ToError(err1)
	return publicKey, err
}

// SDFHashUpdate 44.多包杂凑运算
func (c *Ctx) SDFHashUpdate(sessionHandle SessionHandleType, pucData []byte, uiDataLength uint) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFHashUpdate(c.libHandle, C.SGD_HANDLE(sessionHandle), CMessage(pucData), C.SGD_UINT32(uiDataLength))
	err = ToError(err1)
	return err
}

// SDFHashFinal 45.杂凑运算结束
func (c *Ctx) SDFHashFinal(sessionHandle SessionHandleType) (hash []byte, hashLength uint, err error) {
	var err1 C.SGD_RV
	var pucData C.SGD_UCHAR_PRT
	var puiHashLength C.SGD_UINT32
	err1 = C.SDFHashFinal(c.libHandle, C.SGD_HANDLE(sessionHandle), &pucData, &puiHashLength)
	hash = C.GoBytes(unsafe.Pointer(pucData), C.int(puiHashLength))
	hashLength = uint(puiHashLength)
	C.free(unsafe.Pointer(pucData))
	err = ToError(err1)
	return hash, hashLength, err
}

// SDFGetSymmKeyHandle 50.
func (c *Ctx) SDFGetSymmKeyHandle(sessionHandle SessionHandleType, uiKeyIndex uint) (keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFGetSymmKeyHandle(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyIndex), &phKeyHandle)
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return keyHandle, err
}

// SDFInternalEncrypt_ECC 51. ECC方式的加密
func (c *Ctx) SDFInternalEncrypt_ECC(sessionHandle SessionHandleType, uiISKIndex uint, uiAlgID uint, pucData []byte, uiDataLength uint) (encData ECCCipher, err error) {
	var err1 C.SGD_RV
	var pucEncData C.ECCCipher
	err1 = C.SDFInternalEncrypt_ECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiISKIndex), C.SGD_UINT32(uiAlgID), CMessage(pucData), C.SGD_UINT32(uiDataLength), &pucEncData)
	encData = ConvertToECCCipherGo(pucEncData)
	err = ToError(err1)
	return encData, err
}

// SDFInternalDecrypt_ECC 52. ECC方式的解密
func (c *Ctx) SDFInternalDecrypt_ECC(sessionHandle SessionHandleType, uiISKIndex uint, uiAlgID uint, encData ECCCipher) (data []byte, dataLength uint, err error) {
	var err1 C.SGD_RV
	var pucEncData C.ECCCipher
	for i := 0; i < len(encData.X); i++ {
		pucEncData.x[i] = C.SGD_UCHAR(encData.X[i])
	}
	for i := 0; i < len(encData.Y); i++ {
		pucEncData.y[i] = C.SGD_UCHAR(encData.Y[i])
	}
	for i := 0; i < len(encData.M); i++ {
		pucEncData.M[i] = C.SGD_UCHAR(encData.M[i])
	}
	pucEncData.L = C.SGD_UINT32(encData.L)
	for i := 0; i < len(encData.C); i++ {
		pucEncData.C[i] = C.SGD_UCHAR(encData.C[i])
	}
	var pucData C.SGD_UCHAR_PRT
	var puiDataLength C.SGD_UINT32
	err1 = C.SDFInternalDecrypt_ECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiISKIndex), C.SGD_UINT32(uiAlgID), &pucEncData, &pucData, &puiDataLength)
	data = C.GoBytes(unsafe.Pointer(pucData), C.int(puiDataLength))
	C.free(unsafe.Pointer(pucData))
	dataLength = uint(puiDataLength)
	err = ToError(err1)
	return data, dataLength, err
}

// SDFExportKeyWithEPK_ECC 54. EPK方式导出ECC密钥
func (c *Ctx) SDFExportKeyWithEPK_ECC(sessionHandle SessionHandleType, hKeyHandle KeyHandleType, uiAlgID uint, publicKey ECCrefPublicKey) (key ECCCipher, err error) {
	var err1 C.SGD_RV
	var pucKey C.ECCCipher
	pucPublicKey := ConvertToECCrefPublicKeyC(publicKey)
	err1 = C.SDFExportKeyWithEPK_ECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_HANDLE(hKeyHandle), C.SGD_UINT32(uiAlgID), &pucPublicKey, &pucKey)
	key = ConvertToECCCipherGo(pucKey)
	err = ToError(err1)
	return key, err
}

// SDFExportKeyWithKEK 55. EPK方式导出密钥
func (c *Ctx) SDFExportKeyWithKEK(sessionHandle SessionHandleType, hKeyHandle KeyHandleType, uiAlgID uint, uiKEKIndex uint) (key []byte, err error) {
	var err1 C.SGD_RV
	var pucKey C.SGD_UCHAR_PRT
	var puiKeyLength C.SGD_UINT32
	err1 = C.SDFExportKeyWithKEK(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_HANDLE(hKeyHandle), C.SGD_UINT32(uiAlgID), C.SGD_UINT32(uiKEKIndex), &pucKey, &puiKeyLength)
	key = C.GoBytes(unsafe.Pointer(pucKey), C.int(puiKeyLength))
	C.free(unsafe.Pointer(pucKey))
	err = ToError(err1)
	return key, err
}
