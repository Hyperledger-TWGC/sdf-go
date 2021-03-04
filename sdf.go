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

typedef SGD_HANDLE*  SGD_HANDLE_PRT;
typedef SGD_UCHAR*   SGD_UCHAR_PRT;


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

SGD_RV OpenDevice(struct LibHandle * h,SGD_HANDLE *phDeviceHandle)
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

SGD_RV CloseDevice(struct LibHandle * h,SGD_HANDLE hDeviceHandle)
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

SGD_RV OpenSession(struct LibHandle * h,SGD_HANDLE hDeviceHandle, SGD_HANDLE *phSessionHandle)
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

SGD_RV CloseSession(struct LibHandle * h,SGD_HANDLE hSessionHandle)
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

SGD_RV GetDeviceInfo(struct LibHandle * h,SGD_HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo)
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

SGD_RV GenerateRandom(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiLength, SGD_UCHAR_PRT *pucRandom)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,SGD_UCHAR*);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateRandom");
	return (*fptr)(hSessionHandle,uiLength,*pucRandom);
#else
	*pucRandom = calloc(uiLength, sizeof(SGD_UCHAR));
	if (*pucRandom == NULL) {
		return SGD_FALSE;
	}
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateRandom");
	return (*fptr)(hSessionHandle,uiLength,*pucRandom);
#endif

}

SGD_RV GetPrivateKeyAccessRight(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex,SGD_UCHAR_PRT *pucPassword, SGD_UINT32  uiPwdLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,SGD_UCHAR*,SGD_UINT32);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GetPrivateKeyAccessRight");
	return (*fptr)(hSessionHandle,uiKeyIndex,*pucPassword,uiPwdLength);
#else
	*pucPassword = calloc(uiPwdLength, sizeof(SGD_UCHAR));
	if (*pucPassword == NULL) {
		return SGD_FALSE;
	}
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GetPrivateKeyAccessRight");
	return (*fptr)(hSessionHandle,uiKeyIndex,*pucPassword,uiPwdLength);
#endif
}

SGD_RV ReleasePrivateKeyAccessRight(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex)
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

SGD_RV ExportSignPublicKey_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey)
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
SGD_RV ExportEncPublicKey_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey)
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
SGD_RV GenerateKeyPair_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyBits,RSArefPublicKey *pucPublicKey,RSArefPrivateKey *pucPrivateKey)
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
SGD_RV GenerateKeyWithIPK_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR_PRT *pucKey,SGD_UINT32 *puiKeyLength,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,SGD_UINT32,SGD_UCHAR*,SGD_UINT32*,SGD_HANDLE*);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateKeyWithIPK_RSA");
	return (*fptr)(hSessionHandle,uiIPKIndex,uiKeyBits,*pucKey,puiKeyLength,phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateKeyWithIPK_RSA");
	return (*fptr)(hSessionHandle,uiIPKIndex,uiKeyBits,*pucKey,puiKeyLength,phKeyHandle);
#endif
}
SGD_RV GenerateKeyWithEPK_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits,RSArefPublicKey *pucPublicKey,SGD_UCHAR_PRT *pucKey,SGD_UINT32 *puiKeyLength,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,RSArefPublicKey*,SGD_UCHAR*,SGD_UINT32*,SGD_HANDLE*);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateKeyWithEPK_RSA");
	return (*fptr)(hSessionHandle,uiKeyBits,pucPublicKey,*pucKey,puiKeyLength,phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle,"SDF_GenerateKeyWithEPK_RSA");
	return (*fptr)(hSessionHandle,uiKeyBits,pucPublicKey,*pucKey,puiKeyLength,phKeyHandle);
#endif
}

SGD_RV ImportKeyWithISK_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,SGD_UCHAR_PRT *pucKey,SGD_UINT32 uiKeyLength,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,SGD_UCHAR*,SGD_UINT32,SGD_HANDLE*);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ImportKeyWithISK_RSA");
	return (*fptr)(hSessionHandle,uiISKIndex,*pucKey,uiKeyLength,phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ImportKeyWithISK_RSA");
	return (*fptr)(hSessionHandle,uiISKIndex,*pucKey,uiKeyLength,phKeyHandle);
#endif
}
SGD_RV ExchangeDigitEnvelopeBaseOnRSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey,SGD_UCHAR_PRT *pucDEInput,SGD_UINT32  uiDELength,SGD_UCHAR_PRT *pucDEOutput,SGD_UINT32  *puiDELength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UINT32,RSArefPublicKey*,SGD_UCHAR*,SGD_UINT32,SGD_UCHAR*,SGD_UINT32*);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExchangeDigitEnvelopeBaseOnRSA");
	return (*fptr)(hSessionHandle,uiKeyIndex,pucPublicKey,*pucDEInput,uiDELength,*pucDEOutput,puiDELength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExchangeDigitEnvelopeBaseOnRSA");
	return (*fptr)(hSessionHandle,uiKeyIndex,pucPublicKey,*pucDEInput,uiDELength,*pucDEOutput,puiDELength);
#endif
}
SGD_RV ExportSignPublicKey_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,ECCrefPublicKey *pucPublicKey)
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
SGD_RV ExportEncPublicKey_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,ECCrefPublicKey *pucPublicKey)
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
SGD_RV GenerateKeyPair_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiAlgID,SGD_UINT32  uiKeyBits,ECCrefPublicKey *pucPublicKey,ECCrefPrivateKey *pucPrivateKey)
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
SGD_RV GenerateKeyWithIPK_ECC (struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex,SGD_UINT32 uiKeyBits,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle)
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
SGD_RV GenerateKeyWithEPK_ECC (struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits,SGD_UINT32  uiAlgID,ECCrefPublicKey *pucPublicKey,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle)
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
SGD_RV ImportKeyWithISK_ECC (struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiISKIndex,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle)
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
SGD_RV GenerateAgreementDataWithECC (struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR_PRT *pucSponsorID,SGD_UINT32 uiSponsorIDLength,ECCrefPublicKey  *pucSponsorPublicKey,ECCrefPublicKey  *pucSponsorTmpPublicKey,SGD_HANDLE *phAgreementHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UINT32 ,SGD_UINT32 ,SGD_UCHAR *,SGD_UINT32 ,ECCrefPublicKey  *,ECCrefPublicKey  *,SGD_HANDLE *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateAgreementDataWithECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, uiKeyBits, *pucSponsorID, uiSponsorIDLength,  pucSponsorPublicKey,  pucSponsorTmpPublicKey, phAgreementHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateAgreementDataWithECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, uiKeyBits, *pucSponsorID, uiSponsorIDLength,  pucSponsorPublicKey,  pucSponsorTmpPublicKey, phAgreementHandle);
#endif
}
SGD_RV GenerateKeyWithECC (struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UCHAR_PRT *pucResponseID,SGD_UINT32 uiResponseIDLength,ECCrefPublicKey *pucResponsePublicKey,ECCrefPublicKey *pucResponseTmpPublicKey,SGD_HANDLE hAgreementHandle,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE, SGD_UCHAR *,SGD_UINT32 ,ECCrefPublicKey *,ECCrefPublicKey *,SGD_HANDLE ,SGD_HANDLE *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateKeyWithECC");
	return (*fptr)(hSessionHandle,*pucResponseID,uiResponseIDLength,pucResponsePublicKey,pucResponseTmpPublicKey,hAgreementHandle,phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateKeyWithECC");
	return (*fptr)(hSessionHandle,*pucResponseID,uiResponseIDLength,pucResponsePublicKey,pucResponseTmpPublicKey,hAgreementHandle,phKeyHandle);
#endif
}
SGD_RV GenerateAgreementDataAndKeyWithECC (struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR_PRT *pucResponseID,SGD_UINT32 uiResponseIDLength,SGD_UCHAR_PRT *pucSponsorID,SGD_UINT32 uiSponsorIDLength,ECCrefPublicKey *pucSponsorPublicKey,ECCrefPublicKey *pucSponsorTmpPublicKey,ECCrefPublicKey  *pucResponsePublicKey,	ECCrefPublicKey  *pucResponseTmpPublicKey,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UINT32 ,SGD_UINT32 ,SGD_UCHAR *,SGD_UINT32 ,SGD_UCHAR *,SGD_UINT32 ,ECCrefPublicKey *,ECCrefPublicKey *,ECCrefPublicKey  *,	ECCrefPublicKey  *,SGD_HANDLE *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateAgreementDataAndKeyWithECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, uiKeyBits, *pucResponseID, uiResponseIDLength, *pucSponsorID, uiSponsorIDLength, pucSponsorPublicKey, pucSponsorTmpPublicKey,  pucResponsePublicKey,	  pucResponseTmpPublicKey, phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateAgreementDataAndKeyWithECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, uiKeyBits, *pucResponseID, uiResponseIDLength, *pucSponsorID, uiSponsorIDLength, pucSponsorPublicKey, pucSponsorTmpPublicKey,  pucResponsePublicKey,	  pucResponseTmpPublicKey, phKeyHandle);
#endif
}
SGD_RV ExchangeDigitEnvelopeBaseOnECC(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,SGD_UINT32  uiAlgID,ECCrefPublicKey *pucPublicKey,ECCCipher *pucEncDataIn,ECCCipher *pucEncDataOut)
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
SGD_RV GenerateKeyWithKEK(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits,SGD_UINT32  uiAlgID,SGD_UINT32 uiKEKIndex, SGD_UCHAR_PRT *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle)
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
SGD_RV ImportKeyWithKEK(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiAlgID,SGD_UINT32 uiKEKIndex, SGD_UCHAR_PRT *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UINT32  ,SGD_UINT32 , SGD_UCHAR *, SGD_UINT32 , SGD_HANDLE *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ImportKeyWithKEK");
	return (*fptr)(hSessionHandle,  uiAlgID, uiKEKIndex,  *pucKey,  uiKeyLength,  phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ImportKeyWithKEK");
	return (*fptr)(hSessionHandle,  uiAlgID, uiKEKIndex,  *pucKey,  uiKeyLength,  phKeyHandle);
#endif
}
SGD_RV DestroyKey(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle)
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



SGD_RV ExternalPublicKeyOperation_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, RSArefPublicKey *pucPublicKey,SGD_UCHAR_PRT *pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR_PRT *pucDataOutput,SGD_UINT32  *puiOutputLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , RSArefPublicKey *,SGD_UCHAR *,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExternalPublicKeyOperation_RSA");
	return (*fptr)(hSessionHandle,  pucPublicKey, *pucDataInput,  uiInputLength, *pucDataOutput,  puiOutputLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExternalPublicKeyOperation_RSA");
	return (*fptr)(hSessionHandle,  pucPublicKey, *pucDataInput,  uiInputLength, *pucDataOutput,  puiOutputLength);
#endif
}

SGD_RV InternalPublicKeyOperation_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SGD_UCHAR_PRT *pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR_PRT *pucDataOutput,SGD_UINT32  *puiOutputLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_InternalPublicKeyOperation_RSA");
	return (*fptr)(hSessionHandle,  uiKeyIndex, *pucDataInput,  uiInputLength, *pucDataOutput,  puiOutputLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_InternalPublicKeyOperation_RSA");
	return (*fptr)(hSessionHandle,  uiKeyIndex, *pucDataInput,  uiInputLength, *pucDataOutput,  puiOutputLength);
#endif
}
SGD_RV InternalPrivateKeyOperation_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SGD_UCHAR_PRT *pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR_PRT *pucDataOutput,SGD_UINT32  *puiOutputLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_InternalPrivateKeyOperation_RSA");
	return (*fptr)(hSessionHandle,  uiKeyIndex, *pucDataInput,uiInputLength,*pucDataOutput,puiOutputLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_InternalPrivateKeyOperation_RSA");
	return (*fptr)(hSessionHandle,  uiKeyIndex, *pucDataInput,uiInputLength,*pucDataOutput,puiOutputLength);
#endif
}

SGD_RV ExternalVerify_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR_PRT *pucDataInput,SGD_UINT32  uiInputLength,ECCSignature *pucSignature)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32 ,ECCrefPublicKey *,SGD_UCHAR *,SGD_UINT32  ,ECCSignature *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExternalVerify_ECC");
	return (*fptr)(hSessionHandle, uiAlgID, pucPublicKey, *pucDataInput,  uiInputLength, pucSignature);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExternalVerify_ECC");
	return (*fptr)(hSessionHandle, uiAlgID, pucPublicKey, *pucDataInput,  uiInputLength, pucSignature);
#endif
}
SGD_RV InternalSign_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UCHAR_PRT *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32  uiISKIndex,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_InternalSign_ECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, *pucData,  uiDataLength, pucSignature);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_InternalSign_ECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, *pucData,  uiDataLength, pucSignature);
#endif
}
SGD_RV InternalVerify_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UCHAR_PRT *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32  ,ECCSignature *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_InternalVerify_ECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, *pucData,  uiDataLength, pucSignature)；
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_InternalVerify_ECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, *pucData,  uiDataLength, pucSignature);
#endif
}
SGD_RV ExternalEncrypt_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR_PRT *pucData,SGD_UINT32  uiDataLength,ECCCipher *pucEncData)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32 ,ECCrefPublicKey *,SGD_UCHAR *,SGD_UINT32  ,ECCCipher *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExternalEncrypt_ECC");
	return (*fptr)(hSessionHandle, uiAlgID, pucPublicKey, *pucData,  uiDataLength, pucEncData);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExternalEncrypt_ECC");
	return (*fptr)(hSessionHandle, uiAlgID, pucPublicKey, *pucData,  uiDataLength, pucEncData);
#endif
}

SGD_RV Encrypt(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR_PRT *pucIV,SGD_UCHAR_PRT *pucData,SGD_UINT32 uiDataLength,SGD_UCHAR_PRT *pucEncData,SGD_UINT32  *puiEncDataLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_HANDLE ,SGD_UINT32 ,SGD_UCHAR *,SGD_UCHAR *,SGD_UINT32 ,SGD_UCHAR *,SGD_UINT32  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_Encrypt");
	return (*fptr)(hSessionHandle, hKeyHandle, uiAlgID, *pucIV, *pucData, uiDataLength, *pucEncData,  puiEncDataLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_Encrypt");
	return (*fptr)(hSessionHandle, hKeyHandle, uiAlgID, *pucIV, *pucData, uiDataLength, *pucEncData,  puiEncDataLength);
#endif
}
SGD_RV Decrypt (struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR_PRT *pucIV,SGD_UCHAR_PRT *pucEncData,SGD_UINT32  uiEncDataLength,SGD_UCHAR_PRT *pucData,SGD_UINT32 *puiDataLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_HANDLE ,SGD_UINT32 ,SGD_UCHAR *,SGD_UCHAR *,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32 *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_Decrypt");
	return (*fptr)(hSessionHandle, hKeyHandle, uiAlgID, *pucIV, *pucEncData,  uiEncDataLength, *pucData, puiDataLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_Decrypt");
	return (*fptr)(hSessionHandle, hKeyHandle, uiAlgID, *pucIV, *pucEncData,  uiEncDataLength, *pucData, puiDataLength);
#endif
}
SGD_RV CalculateMAC(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR_PRT *pucIV,SGD_UCHAR_PRT *pucData,SGD_UINT32 uiDataLength,SGD_UCHAR_PRT *pucMAC,SGD_UINT32  *puiMACLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_HANDLE ,SGD_UINT32 ,SGD_UCHAR *,SGD_UCHAR *,SGD_UINT32 ,SGD_UCHAR *,SGD_UINT32  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_CalculateMAC");
	return (*fptr)(hSessionHandle, hKeyHandle, uiAlgID, *pucIV, *pucData, uiDataLength, *pucMAC,  puiMACLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_CalculateMAC");
	return (*fptr)(hSessionHandle, hKeyHandle, uiAlgID, *pucIV, *pucData, uiDataLength, *pucMAC,  puiMACLength);
#endif
}


SGD_RV CreateFile(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT *pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiFileSize)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UCHAR *,SGD_UINT32 ,SGD_UINT32 );
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_CreateFile");
	return (*fptr)(hSessionHandle, *pucFileName, uiNameLen, uiFileSize);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_CreateFile");
	return (*fptr)(hSessionHandle, *pucFileName, uiNameLen, uiFileSize);

#endif
}
SGD_RV ReadFile(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT *pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiOffset,SGD_UINT32 *puiReadLength,SGD_UCHAR_PRT *pucBuffer)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UCHAR *,SGD_UINT32 ,SGD_UINT32 ,SGD_UINT32 *,SGD_UCHAR *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ReadFile");
	return (*fptr)(hSessionHandle, *pucFileName, uiNameLen, uiOffset, puiReadLength, *pucBuffer);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ReadFile");
	return (*fptr)(hSessionHandle, *pucFileName, uiNameLen, uiOffset, puiReadLength, *pucBuffer);
#endif
}
SGD_RV WriteFile(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT *pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiOffset,SGD_UINT32 uiWriteLength,SGD_UCHAR_PRT *pucBuffer)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UCHAR *,SGD_UINT32 ,SGD_UINT32 ,SGD_UINT32 ,SGD_UCHAR *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_WriteFile");
	return (*fptr)(hSessionHandle, *pucFileName, uiNameLen, uiOffset, uiWriteLength, *pucBuffer);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_WriteFile");
	return (*fptr)(hSessionHandle, *pucFileName, uiNameLen, uiOffset, uiWriteLength, *pucBuffer);
#endif
}
SGD_RV DeleteFile(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT *pucFileName,SGD_UINT32 uiNameLen)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UCHAR *,SGD_UINT32 );
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_DeleteFile");
	return (*fptr)(hSessionHandle, *pucFileName, uiNameLen);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_DeleteFile");
	return (*fptr)(hSessionHandle, *pucFileName, uiNameLen);
#endif
}


SGD_RV HashInit(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR_PRT *pucID,SGD_UINT32 uiIDLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32 ,ECCrefPublicKey *,SGD_UCHAR *,SGD_UINT32 );
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_HashInit");
	return (*fptr)(hSessionHandle, uiAlgID, pucPublicKey, *pucID, uiIDLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_HashInit");
	return (*fptr)(hSessionHandle, uiAlgID, pucPublicKey, *pucID, uiIDLength);
#endif
}
SGD_RV HashUpdate(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT *pucData,SGD_UINT32  uiDataLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UCHAR *,SGD_UINT32  );
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_HashUpdate");
	return (*fptr)(hSessionHandle, *pucData,  uiDataLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_HashUpdate");
	return (*fptr)(hSessionHandle, *pucData,  uiDataLength);
#endif
}
SGD_RV HashFinal(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT *pucHash,SGD_UINT32  *puiHashLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UCHAR *,SGD_UINT32  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_HashFinal");
	return (*fptr)(hSessionHandle, *pucHash,  puiHashLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_HashFinal");
	return (*fptr)(hSessionHandle, *pucHash,  puiHashLength);
#endif
}



SGD_RV GetSymmKeyHandle(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_HANDLE *phKeyHandle)
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
SGD_RV ImportKey(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UCHAR_PRT *pucKey, SGD_UINT32 uiKeyLength,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UCHAR *, SGD_UINT32 ,SGD_HANDLE *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ImportKey");
	return (*fptr)(hSessionHandle,  *pucKey,  uiKeyLength, phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ImportKey");
	return (*fptr)(hSessionHandle,  *pucKey,  uiKeyLength, phKeyHandle);
#endif
}
SGD_RV ExternalPrivateKeyOperation_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, RSArefPrivateKey *pucPrivateKey,SGD_UCHAR_PRT *pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR_PRT *pucDataOutput,SGD_UINT32  *puiOutputLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , RSArefPrivateKey *,SGD_UCHAR *,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExternalPrivateKeyOperation_RSA");
	return (*fptr)(hSessionHandle,  pucPrivateKey, *pucDataInput,  uiInputLength, *pucDataOutput,  puiOutputLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExternalPrivateKeyOperation_RSA");
	return (*fptr)(hSessionHandle,  pucPrivateKey, *pucDataInput,  uiInputLength, *pucDataOutput,  puiOutputLength);
#endif
}
SGD_RV ExternalSign_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPrivateKey *pucPrivateKey,SGD_UCHAR_PRT *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32 ,ECCrefPrivateKey *,SGD_UCHAR *,SGD_UINT32  ,ECCSignature *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExternalSign_ECC");
	return (*fptr)(hSessionHandle, uiAlgID, pucPrivateKey, *pucData,  uiDataLength, pucSignature);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExternalSign_ECC");
	return (*fptr)(hSessionHandle, uiAlgID, pucPrivateKey, *pucData,  uiDataLength, pucSignature);
#endif
}
SGD_RV ExternalDecrypt_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPrivateKey *pucPrivateKey,ECCCipher *pucEncData,SGD_UCHAR_PRT *pucData,SGD_UINT32  *puiDataLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32 ,ECCrefPrivateKey *,ECCCipher *,SGD_UCHAR *,SGD_UINT32  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExternalDecrypt_ECC");
	return (*fptr)(hSessionHandle, uiAlgID, pucPrivateKey, pucEncData, *pucData,  puiDataLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExternalDecrypt_ECC");
	return (*fptr)(hSessionHandle, uiAlgID, pucPrivateKey, pucEncData, *pucData,  puiDataLength);
#endif
}
SGD_RV InternalDecrypt_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UINT32 uiAlgID,ECCCipher *pucEncData,SGD_UCHAR_PRT *pucData,SGD_UINT32  *puiDataLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32  ,SGD_UINT32 ,ECCCipher *,SGD_UCHAR *,SGD_UINT32  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_InternalDecrypt_ECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, uiAlgID, pucEncData, *pucData,  puiDataLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_InternalDecrypt_ECC");
	return (*fptr)(hSessionHandle,  uiISKIndex, uiAlgID, pucEncData, *pucData,  puiDataLength);
#endif
}
SGD_RV InternalEncrypt_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR_PRT *pucData, SGD_UINT32  uiDataLength, ECCCipher *pucEncData)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UINT32  , SGD_UINT32 , SGD_UCHAR *, SGD_UINT32  , ECCCipher *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_InternalEncrypt_ECC");
	return (*fptr)(hSessionHandle,   uiISKIndex,  uiAlgID,  *pucData,   uiDataLength,  pucEncData);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_InternalEncrypt_ECC");
	return (*fptr)(hSessionHandle,   uiISKIndex,  uiAlgID,  *pucData,   uiDataLength,  pucEncData);
#endif
}


SGD_RV ExportKeyWithEPK_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, RSArefPublicKey *pucPublicKey, SGD_UCHAR_PRT *pucKey, SGD_UINT32 *puiKeyLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_HANDLE , RSArefPublicKey *, SGD_UCHAR *, SGD_UINT32 *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExportKeyWithEPK_RSA");
	return (*fptr)(hSessionHandle,  hKeyHandle,  pucPublicKey,  *pucKey,  puiKeyLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExportKeyWithEPK_RSA");
	return (*fptr)(hSessionHandle,  hKeyHandle,  pucPublicKey,  *pucKey,  puiKeyLength);
#endif
}
SGD_RV ExportKeyWithEPK_ECC(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey)
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
SGD_RV ExportKeyWithKEK(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiKEKIndex, SGD_UCHAR_PRT *pucKey, SGD_UINT32 *puiKeyLength)
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


SGD_RV ExportSignMasterPublicKey_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SM9refSignMasterPublicKey *pPublicKey)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32  ,SM9refSignMasterPublicKey *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExportSignMasterPublicKey_SM9");
	return (*fptr)(hSessionHandle,  uiKeyIndex, pPublicKey);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExportSignMasterPublicKey_SM9");
	return (*fptr)(hSessionHandle,  uiKeyIndex, pPublicKey);
#endif
}
SGD_RV ExportEncMasterPublicKey_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SM9refEncMasterPublicKey *pPublicKey)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32  ,SM9refEncMasterPublicKey *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExportEncMasterPublicKey_SM9");
	return (*fptr)(hSessionHandle, uiKeyIndex, pPublicKey);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExportEncMasterPublicKey_SM9");
	return (*fptr)(hSessionHandle, uiKeyIndex, pPublicKey);
#endif
}
SGD_RV ExportSignMasterKeyPairG_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SGD_UCHAR_PRT *pPairG,SGD_UINT32 *puiPairGLen)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32 *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExportSignMasterKeyPairG_SM9");
	return (*fptr)(hSessionHandle,  uiKeyIndex, *pPairG, puiPairGLen);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExportSignMasterKeyPairG_SM9");
	return (*fptr)(hSessionHandle,  uiKeyIndex, *pPairG, puiPairGLen);
#endif
}
SGD_RV ExportEncMasterKeyPairG_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SGD_UCHAR_PRT *pPairG,SGD_UINT32 *puiPairGLen)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32 *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExportEncMasterKeyPairG_SM9");
	return (*fptr)(hSessionHandle,  uiKeyIndex, *pPairG, puiPairGLen);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExportEncMasterKeyPairG_SM9");
	return (*fptr)(hSessionHandle,  uiKeyIndex, *pPairG, puiPairGLen);
#endif
}
SGD_RV ImportUserSignPrivateKey_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiKeyIndex,SM9refSignUserPrivateKey  *pUserPrivateKey)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32 ,SM9refSignUserPrivateKey  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ImportUserSignPrivateKey_SM9");
	return (*fptr)(hSessionHandle, uiKeyIndex,  pUserPrivateKey);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ImportUserSignPrivateKey_SM9");
	return (*fptr)(hSessionHandle, uiKeyIndex,  pUserPrivateKey);
#endif
}
SGD_RV ImportUserEncPrivateKey_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SM9refEncUserPrivateKey  *pUserPrivateKey)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UINT32 , SM9refEncUserPrivateKey  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ImportUserEncPrivateKey_SM9");
	return (*fptr)(hSessionHandle,  uiKeyIndex,   pUserPrivateKey);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ImportUserEncPrivateKey_SM9");
	return (*fptr)(hSessionHandle,  uiKeyIndex,   pUserPrivateKey);
#endif
}
SGD_RV GenerateSignUserPrivateKey_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR hid, SGD_UCHAR_PRT *pucUserID, SGD_UINT32 uiUserIDLen, SM9refSignUserPrivateKey  *pUserPrivateKey)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UINT32 , SGD_UCHAR , SGD_UCHAR *, SGD_UINT32 , SM9refSignUserPrivateKey  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateSignUserPrivateKey_SM9");
	return (*fptr)(hSessionHandle,  uiKeyIndex,  hid,  *pucUserID,  uiUserIDLen,   pUserPrivateKey);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateSignUserPrivateKey_SM9");
	return (*fptr)(hSessionHandle,  uiKeyIndex,  hid,  *pucUserID,  uiUserIDLen,   pUserPrivateKey);
#endif
}
SGD_RV GenerateEncUserPrivateKey_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR hid,SGD_UCHAR_PRT *pucUserID,SGD_UINT32 uiUserIDLen,SM9refEncUserPrivateKey  *pUserPrivateKey)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UINT32 , SGD_UCHAR ,SGD_UCHAR *,SGD_UINT32 ,SM9refEncUserPrivateKey  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateEncUserPrivateKey_SM9");
	return (*fptr)(hSessionHandle,  uiKeyIndex,  hid, *pucUserID, uiUserIDLen,  pUserPrivateKey);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateEncUserPrivateKey_SM9");
	return (*fptr)(hSessionHandle,  uiKeyIndex,  hid, *pucUserID, uiUserIDLen,  pUserPrivateKey);
#endif
}
SGD_RV Sign_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiKeyIndex,SM9refSignUserPrivateKey  *pUserPrivateKey,SM9refSignMasterPublicKey *pMasterPublicKey,SGD_UCHAR_PRT *pucDataInput,SGD_UINT32 uiDataInputLen,SM9Signature  *pSignature)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32 ,SM9refSignUserPrivateKey  *,SM9refSignMasterPublicKey *,SGD_UCHAR *,SGD_UINT32 ,SM9Signature  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_Sign_SM9");
	return (*fptr)(hSessionHandle, uiKeyIndex,  pUserPrivateKey, pMasterPublicKey, *pucDataInput, uiDataInputLen,  pSignature);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_Sign_SM9");
	return (*fptr)(hSessionHandle, uiKeyIndex,  pUserPrivateKey, pMasterPublicKey, *pucDataInput, uiDataInputLen,  pSignature);
#endif
}
SGD_RV SignEx_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiKeyIndex,SM9refSignUserPrivateKey  *pUserPrivateKey,SM9refSignMasterPublicKey *pMasterPublicKey,SGD_UCHAR_PRT *pPairG,SGD_UINT32 uiPairGLen,SGD_UCHAR_PRT *pucDataInput,SGD_UINT32 uiDataInputLen,SM9Signature  *pSignature)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32 ,SM9refSignUserPrivateKey  *,SM9refSignMasterPublicKey *,SGD_UCHAR *,SGD_UINT32 ,SGD_UCHAR *,SGD_UINT32 ,SM9Signature  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_SignEx_SM9");
	return (*fptr)(hSessionHandle, uiKeyIndex,  pUserPrivateKey, pMasterPublicKey, *pPairG, uiPairGLen, *pucDataInput, uiDataInputLen,  pSignature);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_SignEx_SM9");
	return (*fptr)(hSessionHandle, uiKeyIndex,  pUserPrivateKey, pMasterPublicKey, *pPairG, uiPairGLen, *pucDataInput, uiDataInputLen,  pSignature);
#endif
}
SGD_RV Verify_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR hid,SGD_UCHAR_PRT *pucUserID,SGD_UINT32  uiUserIDLen,SM9refSignMasterPublicKey  *pMasterPublicKey,SGD_UCHAR_PRT *pucData,SGD_UINT32   uiDataInputLen,SM9Signature  *pSignature)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UCHAR ,SGD_UCHAR *,SGD_UINT32  ,SM9refSignMasterPublicKey  *,SGD_UCHAR *,SGD_UINT32   ,SM9Signature  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_Verify_SM9");
	return (*fptr)(hSessionHandle, hid, *pucUserID,  uiUserIDLen,  pMasterPublicKey, *pucData,   uiDataInputLen,  pSignature);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_Verify_SM9");
	return (*fptr)(hSessionHandle, hid, *pucUserID,  uiUserIDLen,  pMasterPublicKey, *pucData,   uiDataInputLen,  pSignature);
#endif
}
SGD_RV VerifyEx_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR hid,SGD_UCHAR_PRT *pucUserID,SGD_UINT32 uiUserIDLen,SM9refSignMasterPublicKey  *pMasterPublicKey,SGD_UCHAR_PRT *pPairG,SGD_UINT32 uiPairGLen,SGD_UCHAR_PRT *pucData,SGD_UINT32   uiDataInputLen,SM9Signature  *pSignature)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE hSessionHandle,SGD_UCHAR hid,SGD_UCHAR *pucUserID,SGD_UINT32 uiUserIDLen,SM9refSignMasterPublicKey  *pMasterPublicKey,SGD_UCHAR *pPairG,SGD_UINT32 uiPairGLen,SGD_UCHAR *pucData,SGD_UINT32   uiDataInputLen,SM9Signature  *pSignature);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_VerifyEx_SM9");
	return (*fptr)(hSessionHandle, hid, *pucUserID, uiUserIDLen,  pMasterPublicKey, *pPairG, uiPairGLen, *pucData,   uiDataInputLen,  pSignature);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_VerifyEx_SM9");
	return (*fptr)(hSessionHandle, hid, *pucUserID, uiUserIDLen,  pMasterPublicKey, *pPairG, uiPairGLen, *pucData,   uiDataInputLen,  pSignature);
#endif
}
SGD_RV Encrypt_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR hid,SGD_UCHAR_PRT *pucUserID,SGD_UINT32  uiUserIDLen,SM9refEncMasterPublicKey *pPubluicKey,SGD_UCHAR_PRT *pucData,SGD_UINT32   uiDataLength,SM9Cipher *pCipher)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UCHAR ,SGD_UCHAR *,SGD_UINT32  ,SM9refEncMasterPublicKey *,SGD_UCHAR *,SGD_UINT32   ,SM9Cipher *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_Encrypt_SM9");
	return (*fptr)(hSessionHandle, hid, *pucUserID,  uiUserIDLen, pPubluicKey, *pucData,   uiDataLength, pCipher);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_Encrypt_SM9");
	return (*fptr)(hSessionHandle, hid, *pucUserID,  uiUserIDLen, pPubluicKey, *pucData,   uiDataLength, pCipher);
#endif
}
SGD_RV EncryptEx_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR hid,SGD_UCHAR_PRT *pucUserID,SGD_UINT32  uiUserIDLen,SM9refEncMasterPublicKey *pPubluicKey,SGD_UCHAR_PRT *pPairG,SGD_UINT32  nPairGLen,SGD_UCHAR_PRT *pucData,SGD_UINT32   uiDataLength,SM9Cipher *pCipher)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UCHAR ,SGD_UCHAR *,SGD_UINT32  ,SM9refEncMasterPublicKey *,SGD_UCHAR *,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32   ,SM9Cipher *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_EncryptEx_SM9");
	return (*fptr)(hSessionHandle, hid, *pucUserID,  uiUserIDLen, pPubluicKey, *pPairG,  nPairGLen, *pucData,   uiDataLength, pCipher);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_EncryptEx_SM9");
	return (*fptr)(hSessionHandle, hid, *pucUserID,  uiUserIDLen, pPubluicKey, *pPairG,  nPairGLen, *pucData,   uiDataLength, pCipher);
#endif
}
SGD_RV Decrypt_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT *pucUserID,SGD_UINT32  uiUserIDLen,SGD_UINT32 uiKeyIndex,SM9refEncUserPrivateKey  *pUserPrivateKey,SM9Cipher * pCipher,SGD_UCHAR_PRT *pucPlainData,SGD_UINT32  *uiPlainDataLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UCHAR *,SGD_UINT32  ,SGD_UINT32 ,SM9refEncUserPrivateKey  *,SM9Cipher * ,SGD_UCHAR *,SGD_UINT32  *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_Decrypt_SM9");
	return (*fptr)(hSessionHandle, *pucUserID,  uiUserIDLen, uiKeyIndex,  pUserPrivateKey,  pCipher, *pucPlainData,  uiPlainDataLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_Decrypt_SM9");
	return (*fptr)(hSessionHandle, *pucUserID,  uiUserIDLen, uiKeyIndex,  pUserPrivateKey,  pCipher, *pucPlainData,  uiPlainDataLength);
#endif
}
SGD_RV Encap_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR hid,SGD_UCHAR_PRT *pucUserID,SGD_UINT32  uiUserIDLen,SM9refEncMasterPublicKey  *pPublicKey,SGD_UINT32 uiKeyLen,SGD_UCHAR_PRT *pKey,SM9refKeyPackage *pKeyPackage)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UCHAR ,SGD_UCHAR *,SGD_UINT32  ,SM9refEncMasterPublicKey  *,SGD_UINT32 ,SGD_UCHAR *,SM9refKeyPackage *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_Encap_SM9");
	return (*fptr)(hSessionHandle, hid, *pucUserID,  uiUserIDLen,  pPublicKey, uiKeyLen, *pKey, pKeyPackage);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_Encap_SM9");
	return (*fptr)(hSessionHandle, hid, *pucUserID,  uiUserIDLen,  pPublicKey, uiKeyLen, *pKey, pKeyPackage);
#endif
}
SGD_RV Decap_SM9(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT *pucUserID,SGD_UINT32  uiUserIDLen,SGD_UINT32 uiKeyIndex,SM9refEncUserPrivateKey  *pUserPrivateKey,SM9refKeyPackage *pKeyPackage,SGD_UINT32  uiKeyLen,SGD_UCHAR_PRT *pucKey)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UCHAR *,SGD_UINT32  ,SGD_UINT32 ,SM9refEncUserPrivateKey  *,SM9refKeyPackage *,SGD_UINT32  ,SGD_UCHAR *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_Decap_SM9");
	return (*fptr)(hSessionHandle, *pucUserID,  uiUserIDLen, uiKeyIndex,  pUserPrivateKey, pKeyPackage,  uiKeyLen, *pucKey);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_Decap_SM9");
	return (*fptr)(hSessionHandle, *pucUserID,  uiUserIDLen, uiKeyIndex,  pUserPrivateKey, pKeyPackage,  uiKeyLen, *pucKey);
#endif
}
SGD_RV GenerateAgreementDataWithSM9(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UCHAR hid, SGD_UCHAR_PRT *pucResponseID, SGD_UINT32 uiResponseIDLength, SM9refEncMasterPublicKey  *pPublicKey, SM9refEncMasterPublicKey  *pucSponsorTmpPublicKey, SGD_HANDLE *phAgreementHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UCHAR , SGD_UCHAR *, SGD_UINT32 , SM9refEncMasterPublicKey  *, SM9refEncMasterPublicKey  *, SGD_HANDLE *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateAgreementDataWithSM9");
	return (*fptr)(hSessionHandle,  hid,  *pucResponseID,  uiResponseIDLength,   pPublicKey,   pucSponsorTmpPublicKey,  phAgreementHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateAgreementDataWithSM9");
	return (*fptr)(hSessionHandle,  hid,  *pucResponseID,  uiResponseIDLength,   pPublicKey,   pucSponsorTmpPublicKey,  phAgreementHandle);
#endif
}
SGD_RV GenerateAgreemetDataAndKeyWithSM9(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiKeyLen,SGD_UCHAR hid,SGD_UCHAR_PRT * pucResponseID,SGD_UINT32 uiResponseIDLen,SGD_UCHAR_PRT * pucSponsorID,SGD_UINT32 uiSponsorIDLen,SGD_UINT32 uiKeyIndex,SM9refEncUserPrivateKey  *pucResponsePrivateKey,SM9refEncMasterPublicKey *pucPublicKey,SM9refEncMasterPublicKey * pucSponsorTmpPublicKey,SM9refEncMasterPublicKey * pucResponseTmpPublicKey,SGD_UCHAR_PRT *pucHashSB,SGD_UINT32 *puiSBLen,SGD_UCHAR_PRT  *pucHashS2,SGD_UINT32 *puiS2Len,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32 ,SGD_UCHAR ,SGD_UCHAR * ,SGD_UINT32 ,SGD_UCHAR * ,SGD_UINT32 ,SGD_UINT32 ,SM9refEncUserPrivateKey  *,SM9refEncMasterPublicKey *,SM9refEncMasterPublicKey * ,SM9refEncMasterPublicKey * ,SGD_UCHAR *,SGD_UINT32 *,SGD_UCHAR  *,SGD_UINT32 *,SGD_HANDLE *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateAgreemetDataAndKeyWithSM9");
	return (*fptr)(hSessionHandle, uiKeyLen, hid, *pucResponseID, uiResponseIDLen,  *pucSponsorID, uiSponsorIDLen, uiKeyIndex,  pucResponsePrivateKey, pucPublicKey,  pucSponsorTmpPublicKey,  pucResponseTmpPublicKey, *pucHashSB, puiSBLen,  *pucHashS2, puiS2Len, phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateAgreemetDataAndKeyWithSM9");
	return (*fptr)(hSessionHandle, uiKeyLen, hid, *pucResponseID, uiResponseIDLen,  *pucSponsorID, uiSponsorIDLen, uiKeyIndex,  pucResponsePrivateKey, pucPublicKey,  pucSponsorTmpPublicKey,  pucResponseTmpPublicKey, *pucHashSB, puiSBLen,  *pucHashS2, puiS2Len, phKeyHandle);
#endif
}
SGD_RV GenerateKeyWithSM9(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32 uiKeyLen,SGD_UCHAR hid,SGD_UCHAR_PRT *pucSponsorID,SGD_UINT32 uiSponsorIDLen,SGD_UCHAR_PRT *pucResponseID,SGD_UINT32 uiResponseIDLen,SGD_UINT32 uiKeyIndex,SM9refEncUserPrivateKey   *pucSponsorPrivateKey,SM9refEncMasterPublicKey   *pucPublicKey,SM9refEncMasterPublicKey   *pucResponseTmpPublicKey,SGD_UCHAR_PRT *pucHashSB,SGD_UINT32 uiSBLen,SGD_UCHAR_PRT *pucHashSA,SGD_UINT32 *puiSALen,SGD_HANDLE hAgreementHandle,SGD_HANDLE *phKeyHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32 ,SGD_UCHAR ,SGD_UCHAR *,SGD_UINT32 ,SGD_UCHAR *,SGD_UINT32 ,SGD_UINT32 ,SM9refEncUserPrivateKey   *,SM9refEncMasterPublicKey   *,SM9refEncMasterPublicKey   *,SGD_UCHAR *,SGD_UINT32 ,SGD_UCHAR *,SGD_UINT32 *,SGD_HANDLE ,SGD_HANDLE *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateKeyWithSM9");
	return (*fptr)(hSessionHandle, uiKeyLen, hid, *pucSponsorID, uiSponsorIDLen, *pucResponseID, uiResponseIDLen, uiKeyIndex,   pucSponsorPrivateKey,   pucPublicKey,   pucResponseTmpPublicKey, *pucHashSB, uiSBLen, *pucHashSA, puiSALen, hAgreementHandle, phKeyHandle);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateKeyWithSM9");
	return (*fptr)(hSessionHandle, uiKeyLen, hid, *pucSponsorID, uiSponsorIDLen, *pucResponseID, uiResponseIDLen, uiKeyIndex,   pucSponsorPrivateKey,   pucPublicKey,   pucResponseTmpPublicKey, *pucHashSB, uiSBLen, *pucHashSA, puiSALen, hAgreementHandle, phKeyHandle);
#endif
}
SGD_RV GenerateKeyVerifySM9(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_UCHAR_PRT *pHashS2, SGD_UINT32  uiS2Len, SGD_UCHAR_PRT *pHashSA, SGD_UINT32 uiSALen)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , SGD_UCHAR *, SGD_UINT32  , SGD_UCHAR *, SGD_UINT32 );
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_GenerateKeyVerifySM9");
	return (*fptr)(hSessionHandle,  *pHashS2,   uiS2Len,  *pHashSA,  uiSALen);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GenerateKeyVerifySM9");
	return (*fptr)(hSessionHandle,  *pHashS2,   uiS2Len,  *pHashSA,  uiSALen);
#endif
}
*/
import "C"
import (
	"fmt"
	"github.com/yzwskyspace/sdf/core"
	"os"
	"strings"
	"unsafe"
)


func New(libPath string) *Ctx{
	if x:=os.Getenv("SDFHSM_CONF");x==""{
		os.Setenv("SDFHSM_CONF",libPath)
	}else {
		libPath = x
	}

	c := new(Ctx)
	mod := C.CString(libPath)
	defer C.free(unsafe.Pointer(mod))
	c.libHandle = C.New(mod)
	if c.libHandle == nil{
		return nil
	}
	return  c
}
type  Error uint


func (e Error) Error() string{
	return fmt.Sprintf("sdf: 0x%X:%s",uint(e),core.StrErrors[uint(e)])
}

func ToError(e C.SGD_RV)error{
	if e == C.SDR_OK{
		return nil
	}
	return Error(e)

}


type Ctx struct {
	libHandle     *C.struct_LibHandle
}

type DeviceHandleType   C.SGD_HANDLE
type SessionHandleType  C.SGD_HANDLE
type KeyHandleType    C.SGD_HANDLE
type AgreementHandleType C.SGD_HANDLE

//78

func (c *Ctx)SDFOpenDevice(deviceHandle  DeviceHandleType) (DeviceHandleType,error){
    var err C.SGD_RV
    var dH =C.SGD_HANDLE(deviceHandle)
	err = C.OpenDevice(c.libHandle,&dH)
	if ToError(err) != nil {
		return nil, ToError(err)
	}
	return DeviceHandleType(dH),ToError(err)
}

func (c *Ctx)SDFCloseDevice(deviceHandle  DeviceHandleType) error{
	var err C.SGD_RV
	err = C.CloseDevice(c.libHandle,C.SGD_HANDLE(deviceHandle))
	if ToError(err) != nil {
		return ToError(err)
	}
	return nil
}

func (c *Ctx)SDFOpenSession(deviceHandle  DeviceHandleType)  (SessionHandleType,error){
	var err C.SGD_RV
	var s C.SGD_HANDLE
	//err = C.OpenSession(c.libHandle,C.SGD_HANDLE(deviceHandle),C.SGD_HANDLE_PRT(&s))
	err = C.OpenSession(c.libHandle,C.SGD_HANDLE(deviceHandle),&s)
	return SessionHandleType(s),ToError(err)
}

func (c *Ctx)SDFCloseSession(sessionHandle  SessionHandleType) error{

	var err C.SGD_RV
	err = C.CloseSession(c.libHandle,C.SGD_HANDLE(sessionHandle))
	if ToError(err) != nil {
		return ToError(err)
	}
	return nil

}

func (c *Ctx)SDFGetDeviceInfo(sessionHandle  SessionHandleType) (core.DeviceInfo,error){
	var deviceInfo C.DEVICEINFO
	err := C.GetDeviceInfo(c.libHandle,C.SGD_HANDLE(sessionHandle),&deviceInfo)
	info := core.DeviceInfo{
		IssuerName:  strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&deviceInfo.IssuerName[0]), 40)), " "),
		DeviceName:  strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&deviceInfo.DeviceName[0]), 16)), " "),
		DeviceSerial:  strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&deviceInfo.DeviceSerial[0]), 16)), " "),
		DeviceVersion: uint(deviceInfo.DeviceVersion),
		StandardVersion: uint(deviceInfo.StandardVersion),
		SymAlgAbility: uint(deviceInfo.SymAlgAbility),
		HashAlgAbility: uint(deviceInfo.HashAlgAbility),
		BufferSize: uint(deviceInfo.BufferSize),
	}
	temp1:=C.GoBytes(unsafe.Pointer(&deviceInfo.AsymAlgAbility[0]),2)
	temp2:=C.GoBytes(unsafe.Pointer(&deviceInfo.AsymAlgAbility[1]),2)
	info.AsymAlgAbility[0]=uint(temp1[0])
	info.AsymAlgAbility[1]=uint(temp2[0])

	if ToError(err) != nil {
		return info,ToError(err)
	}
	return info,nil
}

func (c *Ctx)SDFGenerateRandom(sessionHandle SessionHandleType,length uint ) ([]byte,error){
	var err C.SGD_RV
	var random C.SGD_UCHAR_PRT
	err = C.GenerateRandom(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(length),&random)
	if ToError(err) != nil {
		return nil, ToError(err)
	}
	h := C.GoBytes(unsafe.Pointer(random), C.int(length))
	C.free(unsafe.Pointer(random))
	return h,ToError(err)
}

func (c *Ctx)SDFGetPrivateKeyAccessRight(sessionHandle SessionHandleType,keyIndex uint,pwdLength uint)([]byte,error){
	var err C.SGD_RV
	var pucPassword C.SGD_UCHAR_PRT
    err = C.GetPrivateKeyAccessRight(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(keyIndex),&pucPassword,C.SGD_UINT32(pwdLength))
	if ToError(err) != nil {
		return nil,ToError(err)
	}
	h := C.GoBytes(unsafe.Pointer(pucPassword), C.int(pwdLength))
	C.free(unsafe.Pointer(pucPassword))
	return h,ToError(err)
}

func (c *Ctx)SDFReleasePrivateKeyAccessRight(sessionHandle SessionHandleType,keyIndex uint) error{

	var err C.SGD_RV
	err = C.ReleasePrivateKeyAccessRight(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(keyIndex))
	if ToError(err) != nil {
		return ToError(err)
	}
	return ToError(err)
}


func (c *Ctx)SDFExportSignPublicKey_RSA(sessionHandle SessionHandleType,keyIndex uint)(core.RSArefPublicKey,error){
	var err C.SGD_RV
	var pucPublicKey C.RSArefPublicKey

	err = C.ExportSignPublicKey_RSA(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(keyIndex),&pucPublicKey)
	publickey :=core.RSArefPublicKey{
		Bits: uint(pucPublicKey.bits),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.m[0]), 256)), " "),
		E: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.e[0]), 256)), " "),
	}

	return publickey,ToError(err)
}

func (c *Ctx)SDFExportEncPublicKey_RSA(sessionHandle SessionHandleType,keyIndex uint)(core.RSArefPublicKey,error){
	var err C.SGD_RV
	var pucPublicKey C.RSArefPublicKey

	err = C.ExportEncPublicKey_RSA(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(keyIndex),&pucPublicKey)
	publickey :=core.RSArefPublicKey{
		Bits: uint(pucPublicKey.bits),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.m[0]), 256)), " "),
		E: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.e[0]), 256)), " "),
	}
	return publickey,ToError(err)
}

func (c *Ctx)SDFGenerateKeyPair_RSA(sessionHandle SessionHandleType,uiKeyBits uint)(core.RSArefPublicKey,core.RSArefPrivateKey,error){

	var err C.SGD_RV
	var pucPublicKey C.RSArefPublicKey
	var pucPrivateKey C.RSArefPrivateKey
	err = C.GenerateKeyPair_RSA(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyBits),&pucPublicKey,&pucPrivateKey)
	publickey :=core.RSArefPublicKey{
		Bits: uint(pucPublicKey.bits),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.m[0]), 256)), " "),
		E: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.e[0]), 256)), " "),
	}
	privatekey :=core.RSArefPrivateKey{
		Bits: uint(pucPublicKey.bits),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.m[0]), 256)), " "),
		E: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.e[0]), 256)), " "),
		D: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.d[0]), 256)), " "),
		Coef: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.coef[0]), 256)), " "),
	}
	privatekey.Prime[0] = strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.prime[0]), 256)), " ")
	privatekey.Prime[1] = strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.prime[1]), 256)), " ")
	privatekey.Pexp[0] = strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.pexp[0]), 256)), " ")
	privatekey.Pexp[1] = strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.pexp[1]), 256)), " ")

	return publickey,privatekey,ToError(err)
}

func (c *Ctx)SDFGenerateKeyWithIPK_RSA(sessionHandle SessionHandleType,uiIPKIndex uint,uiKeyBits uint)([]byte,uint,KeyHandleType,error){
	var err C.SGD_RV
	var length C.SGD_UINT32
	var pucKey C.SGD_UCHAR_PRT
	var phKeyHandle C.SGD_HANDLE
	err = C.GenerateKeyWithIPK_RSA(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiIPKIndex),C.SGD_UINT32(uiKeyBits),&pucKey,&length,&phKeyHandle)
	p := C.GoBytes(unsafe.Pointer(pucKey), C.int(length))
	C.free(unsafe.Pointer(pucKey))
	return p,uint(length),KeyHandleType(phKeyHandle),ToError(err)
}

func (c *Ctx)SDFGenerateKeyWithEPK_RSA(sessionHandle SessionHandleType,uiKeyBits uint)(core.RSArefPublicKey,[]byte,uint,KeyHandleType,error){
	var err C.SGD_RV
	var pucPublicKey C.RSArefPublicKey
	var length C.SGD_UINT32
	var pucKey C.SGD_UCHAR_PRT
	var phKeyHandle C.SGD_HANDLE
	err = C.GenerateKeyWithEPK_RSA(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyBits),&pucPublicKey,&pucKey,&length,&phKeyHandle)
	publickey :=core.RSArefPublicKey{
		Bits: uint(pucPublicKey.bits),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.m[0]), 256)), " "),
		E: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.e[0]), 256)), " "),
	}
	p := C.GoBytes(unsafe.Pointer(pucKey), C.int(length))
	C.free(unsafe.Pointer(pucKey))
	return publickey,p,uint(length),KeyHandleType(phKeyHandle),ToError(err)
}

func (c *Ctx)SDFImportKeyWithISK_RSA(sessionHandle SessionHandleType,uiKeyBits uint,uiKeyLength uint)([]byte,KeyHandleType,error){
	var err C.SGD_RV
	var pucKey C.SGD_UCHAR_PRT
	var phKeyHandle C.SGD_HANDLE
	err = C.ImportKeyWithISK_RSA(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyBits),&pucKey,C.SGD_UINT32(uiKeyLength),&phKeyHandle)
	p := C.GoBytes(unsafe.Pointer(pucKey), C.int(uiKeyLength))
	C.free(unsafe.Pointer(pucKey))
	return p,KeyHandleType(phKeyHandle),ToError(err)
}

func (c *Ctx)SDFExchangeDigitEnvelopeBaseOnRSA(sessionHandle SessionHandleType,uiKeyIndex uint,uiDELength uint)(core.RSArefPublicKey,[]byte,[]byte,error){
	var err C.SGD_RV
	var pucPublicKey C.RSArefPublicKey
	var pucDEInput C.SGD_UCHAR_PRT
	var pucDEOutput C.SGD_UCHAR_PRT
	var puiDELength C.SGD_UINT32
	err = C.ExchangeDigitEnvelopeBaseOnRSA(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),&pucPublicKey,&pucDEInput,C.SGD_UINT32(uiDELength),&pucDEOutput,&puiDELength)
	publickey :=core.RSArefPublicKey{
		Bits: uint(pucPublicKey.bits),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.m[0]), 256)), " "),
		E: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.e[0]), 256)), " "),
	}
	input := C.GoBytes(unsafe.Pointer(pucDEInput), C.int(uiDELength))
	C.free(unsafe.Pointer(pucDEInput))
	output := C.GoBytes(unsafe.Pointer(pucDEOutput), C.int(puiDELength))
	C.free(unsafe.Pointer(pucDEOutput))
	return publickey,input,output,ToError(err)
}
func (c *Ctx)SDFExportSignPublicKey_ECC(sessionHandle SessionHandleType,uiKeyIndex uint)(core.ECCrefPublicKey,error){
	var err C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	err = C.ExportSignPublicKey_ECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),&pucPublicKey)
	publicKey := core.ECCrefPublicKey{
		Bits: uint(pucPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.y[0]), 256)), " "),
	}
	return publicKey,ToError(err)
}

func (c *Ctx)SDFExportEncPublicKey_ECC(sessionHandle SessionHandleType,uiKeyIndex uint)(core.ECCrefPublicKey,error){
	var err C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	err = C.ExportEncPublicKey_ECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),&pucPublicKey)
	publicKey := core.ECCrefPublicKey{
		Bits: uint(pucPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.y[0]), 256)), " "),
	}
	return publicKey,ToError(err)
}

func (c *Ctx)SDFGenerateKeyPair_ECC(sessionHandle SessionHandleType,uiAlgID uint,uiKeyBits uint)(core.ECCrefPublicKey,core.ECCrefPrivateKey,error){
	var err C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	var pucPrivateKey C.ECCrefPrivateKey
	err = C.GenerateKeyPair_ECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiAlgID),C.SGD_UINT32(uiKeyBits),&pucPublicKey,&pucPrivateKey)
	publickey :=core.ECCrefPublicKey{
		Bits: uint(pucPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.y[0]), 256)), " "),
	}
	privatekey :=core.ECCrefPrivateKey{
		Bits: uint(pucPublicKey.bits),
		K: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.K[0]), 256)), " "),
	}

	return publickey,privatekey,ToError(err)

}

func (c *Ctx)SDFGenerateKeyWithIPK_ECC(sessionHandle SessionHandleType,uiIPKIndex uint,uiKeyBits uint)(core.ECCCipher,KeyHandleType,error){
	var err C.SGD_RV
	var pucKey C.ECCCipher
	var phKeyHandle C.SGD_HANDLE
	err = C.GenerateKeyWithIPK_ECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiIPKIndex),C.SGD_UINT32(uiKeyBits),&pucKey,&phKeyHandle)
	key:=core.ECCCipher{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.y[0]), 256)), " "),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.M[0]), 256)), " "),
		L: uint(pucKey.L),
		C: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.C[0]), 256)), " "),
	}
	return key,KeyHandleType(phKeyHandle),ToError(err)
}

func (c *Ctx)SDFGenerateKeyWithEPK_ECC(sessionHandle SessionHandleType,uiKeyBits uint,uiAlgID uint)(core.ECCrefPublicKey,core.ECCCipher,KeyHandleType,error){
	var err C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	var pucKey C.ECCCipher
	var phKeyHandle C.SGD_HANDLE
	err = C.GenerateKeyWithEPK_ECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyBits),C.SGD_UINT32(uiAlgID),&pucPublicKey,&pucKey,&phKeyHandle)
	publicKey := core.ECCrefPublicKey{
		Bits: uint(pucPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.y[0]), 256)), " "),
	}
	key := core.ECCCipher{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.y[0]), 256)), " "),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.M[0]), 256)), " "),
		L: uint(pucKey.L),
		C: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.C[0]), 256)), " "),
	}
	return publicKey,key,KeyHandleType(phKeyHandle),ToError(err)
}


func (c *Ctx)SDFImportKeyWithISK_ECC(sessionHandle SessionHandleType,uiISKIndex uint)(core.ECCCipher,KeyHandleType,error){
	var err C.SGD_RV
	var pucKey C.ECCCipher
	var phKeyHandle C.SGD_HANDLE
	err = C.ImportKeyWithISK_ECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiISKIndex),&pucKey,&phKeyHandle)
	p := core.ECCCipher{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.y[0]), 256)), " "),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.M[0]), 256)), " "),
		L: uint(pucKey.L),
		C: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.C[0]), 256)), " "),
	}
	return p,KeyHandleType(phKeyHandle),ToError(err)
}

func (c *Ctx)SDFGenerateAgreementDataWithECC(sessionHandle SessionHandleType,uiISKIndex uint,uiKeyBits uint,uiSponsorIDLength uint)([]byte,core.ECCrefPublicKey,core.ECCrefPublicKey,AgreementHandleType,error){
	var err C.SGD_RV
	var pucSponsorID C.SGD_UCHAR_PRT
	var pucSponsorPublicKey C.ECCrefPublicKey
	var pucSponsorTmpPublicKey C.ECCrefPublicKey
	var phAgreementHandle C.SGD_HANDLE
	err = C.GenerateAgreementDataWithECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiISKIndex),C.SGD_UINT32(uiKeyBits),&pucSponsorID,C.SGD_UINT32(uiSponsorIDLength),&pucSponsorPublicKey,&pucSponsorTmpPublicKey,&phAgreementHandle)
	sponsorPublicKey := core.ECCrefPublicKey{
		Bits: uint(pucSponsorPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSponsorPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSponsorPublicKey.y[0]), 256)), " "),
	}
	sponsorTmpPublicKey := core.ECCrefPublicKey{
		Bits: uint(pucSponsorPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSponsorPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSponsorPublicKey.y[0]), 256)), " "),
	}
	sponsorID := C.GoBytes(unsafe.Pointer(pucSponsorID), C.int(uiSponsorIDLength))
	C.free(unsafe.Pointer(pucSponsorID))
	return sponsorID,sponsorPublicKey,sponsorTmpPublicKey,AgreementHandleType(phAgreementHandle),ToError(err)
}

func (c *Ctx)SDFGenerateKeyWithECC(sessionHandle SessionHandleType,hAgreementHandle AgreementHandleType)([]byte,core.ECCrefPublicKey,core.ECCrefPublicKey,KeyHandleType,error){
	var err C.SGD_RV
	var pucResponseID C.SGD_UCHAR_PRT
	var uiResponseIDLength C.SGD_UINT32
	var pucResponsePublicKey C.ECCrefPublicKey
	var pucResponseTmpPublicKey C.ECCrefPublicKey
	var phKeyHandle C.SGD_HANDLE
	err = C.GenerateKeyWithECC(c.libHandle,C.SGD_HANDLE(sessionHandle),&pucResponseID,uiResponseIDLength,&pucResponsePublicKey,&pucResponseTmpPublicKey,C.SGD_HANDLE(hAgreementHandle),&phKeyHandle)
	responsePublicKey := core.ECCrefPublicKey{
		Bits: uint(pucResponsePublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucResponsePublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucResponsePublicKey.y[0]), 256)), " "),
	}
	responseTmpPublicKey := core.ECCrefPublicKey{
		Bits: uint(pucResponseTmpPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucResponseTmpPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucResponseTmpPublicKey.y[0]), 256)), " "),
	}
	responseID := C.GoBytes(unsafe.Pointer(pucResponseID), C.int(uiResponseIDLength))
	C.free(unsafe.Pointer(pucResponseID))
	return responseID,responsePublicKey,responseTmpPublicKey,KeyHandleType(phKeyHandle),ToError(err)
}

func (c *Ctx)SDFGenerateAgreementDataAndKeyWithECC(sessionHandle SessionHandleType,uiISKIndex uint,uiKeyBits uint,uiResponseIDLength uint,uiSponsorIDLength uint)([]byte,[]byte,core.ECCrefPublicKey,core.ECCrefPublicKey,core.ECCrefPublicKey,core.ECCrefPublicKey,KeyHandleType,error){
	var err C.SGD_RV
	var pucResponseID C.SGD_UCHAR_PRT
	var pucSponsorID C.SGD_UCHAR_PRT

	var pucSponsorPublicKey C.ECCrefPublicKey
	var pucSponsorTmpPublicKey C.ECCrefPublicKey
	var pucResponsePublicKey C.ECCrefPublicKey
	var pucResponseTmpPublicKey C.ECCrefPublicKey
    var phKeyHandle C.SGD_HANDLE
	err = C.GenerateAgreementDataAndKeyWithECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiISKIndex),C.SGD_UINT32(uiKeyBits),&pucResponseID,C.SGD_UINT32(uiResponseIDLength),&pucSponsorID,C.SGD_UINT32(uiSponsorIDLength),&pucSponsorPublicKey,&pucSponsorTmpPublicKey,&pucResponsePublicKey,&pucResponseTmpPublicKey,&phKeyHandle)
	sponsorPublicKey := core.ECCrefPublicKey{
		Bits: uint(pucSponsorPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSponsorPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSponsorPublicKey.y[0]), 256)), " "),
	}
	sponsorTmpPublicKey := core.ECCrefPublicKey{
		Bits: uint(pucSponsorTmpPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSponsorTmpPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSponsorTmpPublicKey.y[0]), 256)), " "),
	}
	responsePublicKey := core.ECCrefPublicKey{
		Bits: uint(pucResponsePublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucResponsePublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucResponsePublicKey.y[0]), 256)), " "),
	}
	responseTmpPublicKey := core.ECCrefPublicKey{
		Bits: uint(pucResponseTmpPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucResponseTmpPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucResponseTmpPublicKey.y[0]), 256)), " "),
	}
	responseID := C.GoBytes(unsafe.Pointer(pucResponseID), C.int(uiResponseIDLength))
	C.free(unsafe.Pointer(pucResponseID))
	sponsorID := C.GoBytes(unsafe.Pointer(pucSponsorID), C.int(uiSponsorIDLength))
	C.free(unsafe.Pointer(pucSponsorID))
	return responseID,sponsorID,sponsorPublicKey,sponsorTmpPublicKey,responsePublicKey,responseTmpPublicKey,KeyHandleType(phKeyHandle),ToError(err)
}

func (c *Ctx)SDFExchangeDigitEnvelopeBaseOnECC(sessionHandle SessionHandleType,uiKeyIndex uint,uiAlgID uint)(core.ECCrefPublicKey,core.ECCCipher,core.ECCCipher,error){
	var err C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	var pucEncDataIn C.ECCCipher
	var pucEncDataOut C.ECCCipher
	err = C.ExchangeDigitEnvelopeBaseOnECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),C.SGD_UINT32(uiAlgID),&pucPublicKey,&pucEncDataIn,&pucEncDataOut)
	publicKey := core.ECCrefPublicKey{
		Bits: uint(pucPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.y[0]), 256)), " "),
	}
	encDataIn :=core.ECCCipher{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncDataIn.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncDataIn.y[0]), 256)), " "),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncDataIn.M[0]), 256)), " "),
		L: uint(pucEncDataIn.L),
		C: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncDataIn.C[0]), 256)), " "),
	}

	encDataOut :=core.ECCCipher{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncDataOut.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncDataOut.y[0]), 256)), " "),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncDataOut.M[0]), 256)), " "),
		L: uint(pucEncDataOut.L),
		C: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncDataOut.C[0]), 256)), " "),
	}


	return publicKey,encDataIn,encDataOut,ToError(err)
}


func (c *Ctx)SDFGenerateKeyWithKEK(sessionHandle SessionHandleType,uiKeyBits uint,uiAlgID uint,uiKEKIndex uint )([]byte,uint,KeyHandleType,error){
	var err C.SGD_RV
	var pucKey C.SGD_UCHAR_PRT
	var keyLength C.SGD_UINT32
	var phKeyHandle C.SGD_HANDLE
	err = C.GenerateKeyWithKEK(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyBits),C.SGD_UINT32(uiAlgID),C.SGD_UINT32(uiKEKIndex),&pucKey,&keyLength,&phKeyHandle)
	p:= C.GoBytes(unsafe.Pointer(pucKey), C.int(keyLength))
	C.free(unsafe.Pointer(pucKey))
	return p,uint(keyLength),KeyHandleType(phKeyHandle),ToError(err)

}

func (c *Ctx)SDFImportKeyWithKEK(sessionHandle SessionHandleType,uiAlgID uint,uiKEKIndex uint,uiKeyLength uint )([]byte,KeyHandleType,error){
	var err C.SGD_RV
	var pucKey C.SGD_UCHAR_PRT
	var phKeyHandle C.SGD_HANDLE
	err = C.ImportKeyWithKEK(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiAlgID),C.SGD_UINT32(uiKEKIndex),&pucKey,C.SGD_UINT32(uiKeyLength),&phKeyHandle)
	p:= C.GoBytes(unsafe.Pointer(pucKey), C.int(uiKeyLength))
	C.free(unsafe.Pointer(pucKey))
	return p,KeyHandleType(phKeyHandle),ToError(err)
}

func (c *Ctx)SDFDestroyKey(sessionHandle SessionHandleType,hAgreementHandle AgreementHandleType)(error){
	var err C.SGD_RV
	err = C.DestroyKey(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_HANDLE(hAgreementHandle))
	return ToError(err)
}

func (c *Ctx)SDFExternalPublicKeyOperation_RSA(sessionHandle SessionHandleType,uiInputLength uint)(core.RSArefPublicKey,[]byte,[]byte,error){
	var err C.SGD_RV
	var pucPublicKey C.RSArefPublicKey
	var pucDataInput C.SGD_UCHAR_PRT
	var pucDataOutput C.SGD_UCHAR_PRT
	var puiOutputLength C.SGD_UINT32
	err = C.ExternalPublicKeyOperation_RSA(c.libHandle,C.SGD_HANDLE(sessionHandle),&pucPublicKey,&pucDataInput,C.SGD_UINT32(uiInputLength),&pucDataOutput,&puiOutputLength)
	publickey :=core.RSArefPublicKey{
		Bits: uint(pucPublicKey.bits),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.m[0]), 256)), " "),
		E: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.e[0]), 256)), " "),
	}
	dataInput:= C.GoBytes(unsafe.Pointer(pucDataInput), C.int(uiInputLength))
	C.free(unsafe.Pointer(pucDataInput))
	dataOutput:= C.GoBytes(unsafe.Pointer(pucDataOutput), C.int(puiOutputLength))
	C.free(unsafe.Pointer(pucDataOutput))
	return publickey,dataInput,dataOutput,ToError(err)
}

func (c *Ctx)SDFInternalPublicKeyOperation_RSA(sessionHandle SessionHandleType,uiKeyIndex uint,uiInputLength uint)([]byte,[]byte,error){
	var err C.SGD_RV
	var pucDataInput C.SGD_UCHAR_PRT
	var pucDataOutput C.SGD_UCHAR_PRT
	var puiOutputLength C.SGD_UINT32
	err = C.InternalPublicKeyOperation_RSA(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),&pucDataInput,C.SGD_UINT32(uiInputLength),&pucDataOutput,&puiOutputLength)
	dataInput:= C.GoBytes(unsafe.Pointer(pucDataInput), C.int(uiInputLength))
	C.free(unsafe.Pointer(pucDataInput))
	dataOutput:= C.GoBytes(unsafe.Pointer(pucDataOutput), C.int(puiOutputLength))
	C.free(unsafe.Pointer(pucDataOutput))
	return dataInput,dataOutput,ToError(err)
}

func (c *Ctx)SDFInternalPrivateKeyOperation_RSA(sessionHandle SessionHandleType,uiKeyIndex uint,uiInputLength uint)([]byte,[]byte,error){
	var err C.SGD_RV
	var pucDataInput C.SGD_UCHAR_PRT
	var pucDataOutput C.SGD_UCHAR_PRT
	var puiOutputLength C.SGD_UINT32
	err = C.InternalPrivateKeyOperation_RSA(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),&pucDataInput,C.SGD_UINT32(uiInputLength),&pucDataOutput,&puiOutputLength)
	dataInput:= C.GoBytes(unsafe.Pointer(pucDataInput), C.int(uiInputLength))
	C.free(unsafe.Pointer(pucDataInput))
	dataOutput:= C.GoBytes(unsafe.Pointer(pucDataOutput), C.int(puiOutputLength))
	C.free(unsafe.Pointer(pucDataOutput))
	return dataInput,dataOutput,ToError(err)
}

func (c *Ctx)SDFExternalVerify_ECC(sessionHandle SessionHandleType,uiAlgID uint,uiInputLength uint)(core.ECCrefPublicKey,core.ECCSignature,[]byte,error){
	var err C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	var pucSignature C.ECCSignature
	var pucDataInput C.SGD_UCHAR_PRT
	err = C.ExternalVerify_ECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiAlgID),&pucPublicKey,&pucDataInput,C.SGD_UINT32(uiInputLength),&pucSignature)
	publicKey := core.ECCrefPublicKey{
		Bits: uint(pucPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.y[0]), 256)), " "),
	}
	signature :=core.ECCSignature{
		R: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSignature.r[0]), 256)), " "),
		S: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSignature.s[0]), 256)), " "),
	}
	input:= C.GoBytes(unsafe.Pointer(pucDataInput), C.int(uiInputLength))
	C.free(unsafe.Pointer(pucDataInput))
	return publicKey,signature,input,ToError(err)
}

func (c *Ctx)SDFInternalSign_ECC(sessionHandle SessionHandleType,uiISKIndex uint,uiDataLength uint)([]byte,core.ECCSignature,error){
	var err C.SGD_RV
	var pucData C.SGD_UCHAR_PRT
	var pucSignature C.ECCSignature
	C.InternalVerify_ECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiISKIndex),&pucData,C.SGD_UINT32(uiDataLength),&pucSignature)
	signature :=core.ECCSignature{
		R: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSignature.r[0]), 256)), " "),
		S: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSignature.s[0]), 256)), " "),
	}
	data:= C.GoBytes(unsafe.Pointer(pucData), C.int(uiDataLength))
	C.free(unsafe.Pointer(pucData))
	return data,signature,ToError(err)
}

func (c *Ctx)SDFInternalVerify_ECC(sessionHandle SessionHandleType,uiISKIndex uint,uiDataLength uint)([]byte,core.ECCSignature,error){
	var err C.SGD_RV
	var pucData C.SGD_UCHAR_PRT
	var pucSignature C.ECCSignature
	err = C.InternalVerify_ECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiISKIndex),&pucData,C.SGD_UINT32(uiDataLength),&pucSignature)
	signature :=core.ECCSignature{
		R: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSignature.r[0]), 256)), " "),
		S: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSignature.s[0]), 256)), " "),
	}
	data:= C.GoBytes(unsafe.Pointer(pucData), C.int(uiDataLength))
	C.free(unsafe.Pointer(pucData))
	return data,signature,ToError(err)
}


func (c *Ctx)SDFExternalEncrypt_ECC(sessionHandle SessionHandleType,uiAlgID uint,uiDataLength uint)(core.ECCrefPublicKey,[]byte,core.ECCCipher,error){
	var err C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	var pucData C.SGD_UCHAR_PRT
	var pucEncData C.ECCCipher
	err = C.ExternalEncrypt_ECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiAlgID),&pucPublicKey,&pucData,C.SGD_UINT32(uiDataLength),&pucEncData)
	publicKey := core.ECCrefPublicKey{
		Bits: uint(pucPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.y[0]), 256)), " "),
	}
	encDataIn :=core.ECCCipher{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncData.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncData.y[0]), 256)), " "),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncData.M[0]), 256)), " "),
		L: uint(pucEncData.L),
		C: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncData.C[0]), 256)), " "),
	}
	data:= C.GoBytes(unsafe.Pointer(pucData), C.int(uiDataLength))
	C.free(unsafe.Pointer(pucData))
	return publicKey,data,encDataIn,ToError(err)
}


func (c *Ctx)SDFEncrypt(sessionHandle SessionHandleType,hKeyHandle KeyHandleType,uiAlgID uint,uiDataLength uint)([]byte,[]byte,[]byte,error){
	var err C.SGD_RV
	var pucIV C.SGD_UCHAR_PRT
	var pucData C.SGD_UCHAR_PRT
	var pucEncData C.SGD_UCHAR_PRT
	var puiEncDataLength C.SGD_UINT32
	err = C.Encrypt(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_HANDLE(hKeyHandle),C.SGD_UINT32(uiAlgID),&pucIV,&pucData,C.SGD_UINT32(uiDataLength),&pucEncData,&puiEncDataLength)
	iv:= C.GoBytes(unsafe.Pointer(pucIV), C.int(uiDataLength))
	C.free(unsafe.Pointer(pucIV))
	data:= C.GoBytes(unsafe.Pointer(pucData), C.int(uiDataLength))
	C.free(unsafe.Pointer(pucData))
	encData:= C.GoBytes(unsafe.Pointer(pucEncData), C.int(puiEncDataLength))
	C.free(unsafe.Pointer(pucEncData))
	return iv,data,encData,ToError(err)
}

func (c *Ctx)SDFDecrypt(sessionHandle SessionHandleType,hKeyHandle KeyHandleType,uiAlgID uint,uiEncDataLength uint)([]byte,[]byte,[]byte,error){
	var err C.SGD_RV
	var pucIV C.SGD_UCHAR_PRT
	var pucEncData C.SGD_UCHAR_PRT
	var pucData C.SGD_UCHAR_PRT
	var puiDataLength C.SGD_UINT32
	err = C.Decrypt(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_HANDLE(hKeyHandle),C.SGD_UINT32(uiAlgID),&pucIV,&pucEncData,C.SGD_UINT32(uiEncDataLength),&pucData,&puiDataLength)
	iv:= C.GoBytes(unsafe.Pointer(pucIV), C.int(uiEncDataLength))
	C.free(unsafe.Pointer(pucIV))
	encData:= C.GoBytes(unsafe.Pointer(pucEncData), C.int(uiEncDataLength))
	C.free(unsafe.Pointer(pucEncData))
	data:= C.GoBytes(unsafe.Pointer(pucData), C.int(puiDataLength))
	C.free(unsafe.Pointer(pucData))
	return iv,encData,data,ToError(err)
}


func (c *Ctx)SDFCalculateMAC(sessionHandle SessionHandleType,hKeyHandle KeyHandleType,uiAlgID uint,uiDataLength uint)([]byte,[]byte,[]byte,error){
	var err C.SGD_RV
	var pucIV C.SGD_UCHAR_PRT
	var pucData C.SGD_UCHAR_PRT
	var pucMAC C.SGD_UCHAR_PRT
	var puiMACLength C.SGD_UINT32
	err = C.CalculateMAC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_HANDLE(hKeyHandle),C.SGD_UINT32(uiAlgID),&pucIV,&pucData,C.SGD_UINT32(uiDataLength),&pucMAC,&puiMACLength)
	iv:= C.GoBytes(unsafe.Pointer(pucIV), C.int(uiDataLength))
	C.free(unsafe.Pointer(pucIV))
	encData:= C.GoBytes(unsafe.Pointer(pucData), C.int(uiDataLength))
	C.free(unsafe.Pointer(pucData))
	data:= C.GoBytes(unsafe.Pointer(pucMAC), C.int(puiMACLength))
	C.free(unsafe.Pointer(pucMAC))
	return iv,encData,data,ToError(err)
}



func (c *Ctx)SDFCreateFile(sessionHandle SessionHandleType,uiNameLen uint,uiFileSize uint)([]byte,error){
	var err C.SGD_RV
	var pucFileName C.SGD_UCHAR_PRT
	err = C.CreateFile(c.libHandle,C.SGD_HANDLE(sessionHandle),&pucFileName,C.SGD_UINT32(uiNameLen),C.SGD_UINT32(uiFileSize))
	fileName:= C.GoBytes(unsafe.Pointer(pucFileName), C.int(uiNameLen))
	C.free(unsafe.Pointer(pucFileName))
	return fileName,ToError(err)

}

func (c *Ctx)SDFReadFile(sessionHandle SessionHandleType,uiNameLen uint,uiOffset uint)([]byte,[]byte,error){
	var err C.SGD_RV
	var pucFileName C.SGD_UCHAR_PRT
	var puiReadLength C.SGD_UINT32
	var pucBuffer C.SGD_UCHAR_PRT
	err = C.ReadFile(c.libHandle,C.SGD_HANDLE(sessionHandle),&pucFileName,C.SGD_UINT32(uiNameLen),C.SGD_UINT32(uiOffset),&puiReadLength,&pucBuffer)
	fileName:= C.GoBytes(unsafe.Pointer(pucFileName), C.int(uiNameLen))
	C.free(unsafe.Pointer(pucFileName))
	buffer:= C.GoBytes(unsafe.Pointer(pucBuffer), C.int(puiReadLength))
	C.free(unsafe.Pointer(pucBuffer))
	return fileName,buffer,ToError(err)
}


func (c *Ctx)SDFWriteFile(sessionHandle SessionHandleType,uiNameLen uint,uiOffset uint,uiWriteLength uint)([]byte,[]byte,error){
	var err C.SGD_RV
	var pucFileName C.SGD_UCHAR_PRT
	var pucBuffer C.SGD_UCHAR_PRT
	err = C.WriteFile(c.libHandle,C.SGD_HANDLE(sessionHandle),&pucFileName,C.SGD_UINT32(uiNameLen),C.SGD_UINT32(uiOffset),C.SGD_UINT32(uiWriteLength),&pucBuffer)
	fileName:= C.GoBytes(unsafe.Pointer(pucFileName), C.int(uiNameLen))
	C.free(unsafe.Pointer(pucFileName))
	buffer:= C.GoBytes(unsafe.Pointer(pucBuffer), C.int(uiWriteLength))
	C.free(unsafe.Pointer(pucBuffer))
	return fileName,buffer,ToError(err)
}


func (c *Ctx)SDFDeleteFile(sessionHandle SessionHandleType,uiNameLen uint)([]byte,error){
	var err C.SGD_RV
	var pucFileName C.SGD_UCHAR_PRT
	err = C.DeleteFile(c.libHandle,C.SGD_HANDLE(sessionHandle),&pucFileName,C.SGD_UINT32(uiNameLen))
	fileName:= C.GoBytes(unsafe.Pointer(pucFileName), C.int(uiNameLen))
	C.free(unsafe.Pointer(pucFileName))
	return fileName,ToError(err)
}



func (c *Ctx)SDFHashInit(sessionHandle SessionHandleType,uiAlgID uint,uiIDLength uint)(core.ECCrefPublicKey,[]byte,error){
	var err C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	var pucID C.SGD_UCHAR_PRT
	err = C.HashInit(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiAlgID),&pucPublicKey,&pucID,C.SGD_UINT32(uiIDLength))
	publicKey := core.ECCrefPublicKey{
		Bits: uint(pucPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.y[0]), 256)), " "),
	}
	id:= C.GoBytes(unsafe.Pointer(pucID), C.int(uiIDLength))
	C.free(unsafe.Pointer(pucID))
	return publicKey,id,ToError(err)
}


func (c *Ctx)SDFHashUpdate(sessionHandle SessionHandleType,uiDataLength uint)([]byte,error){
	var err C.SGD_RV
	var pucData C.SGD_UCHAR_PRT
	err = C.HashUpdate(c.libHandle,C.SGD_HANDLE(sessionHandle),&pucData,C.SGD_UINT32(uiDataLength))
	data:= C.GoBytes(unsafe.Pointer(pucData), C.int(uiDataLength))
	C.free(unsafe.Pointer(pucData))
	return data,ToError(err)
}


func (c *Ctx)SDFHashFinal(sessionHandle SessionHandleType)([]byte,error){
	var err C.SGD_RV
	var pucData C.SGD_UCHAR_PRT
	var puiHashLength C.SGD_UINT32
	err = C.HashFinal(c.libHandle,C.SGD_HANDLE(sessionHandle),&pucData,&puiHashLength)
	data:= C.GoBytes(unsafe.Pointer(pucData), C.int(puiHashLength))
	C.free(unsafe.Pointer(pucData))
	return data,ToError(err)
}


func (c *Ctx)SDFGetSymmKeyHandle(sessionHandle SessionHandleType,uiKeyIndex uint)(KeyHandleType,error){
	var err C.SGD_RV
	var phKeyHandle C.SGD_HANDLE
	err = C.GetSymmKeyHandle(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),&phKeyHandle)
	return KeyHandleType(phKeyHandle),ToError(err)
}


func (c *Ctx)SDFImportKey(sessionHandle SessionHandleType,uiKeyLength uint)([]byte,KeyHandleType,error){
	var err C.SGD_RV
	var pucKey C.SGD_UCHAR_PRT
	var phKeyHandle C.SGD_HANDLE
	err = C.ImportKey(c.libHandle,C.SGD_HANDLE(sessionHandle),&pucKey,C.SGD_UINT32(uiKeyLength),&phKeyHandle)
	pKey:= C.GoBytes(unsafe.Pointer(pucKey), C.int(uiKeyLength))
	C.free(unsafe.Pointer(pucKey))
	return pKey,KeyHandleType(phKeyHandle),ToError(err)
}


func (c *Ctx)SDFExternalPrivateKeyOperation_RSA(sessionHandle SessionHandleType,uiInputLength uint)(core.RSArefPrivateKey,[]byte,[]byte,error){
	var err C.SGD_RV
	var pucPrivateKey C.RSArefPrivateKey
	var pucDataInput C.SGD_UCHAR_PRT
	var pucDataOutput C.SGD_UCHAR_PRT
	var puiOutputLength C.SGD_UINT32
	err = C.ExternalPrivateKeyOperation_RSA(c.libHandle,C.SGD_HANDLE(sessionHandle),&pucPrivateKey,&pucDataInput,C.SGD_UINT32(uiInputLength),&pucDataOutput,&puiOutputLength)
	privatekey :=core.RSArefPrivateKey{
		Bits: uint(pucPrivateKey.bits),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.m[0]), 256)), " "),
		E: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.e[0]), 256)), " "),
		D: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.d[0]), 256)), " "),
		Coef: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.coef[0]), 256)), " "),
	}
	dataInput:= C.GoBytes(unsafe.Pointer(pucDataInput), C.int(uiInputLength))
	C.free(unsafe.Pointer(pucDataInput))
	dataOutput:= C.GoBytes(unsafe.Pointer(pucDataOutput), C.int(puiOutputLength))
	C.free(unsafe.Pointer(pucDataOutput))
	return privatekey,dataInput,dataOutput,ToError(err)
}

func (c *Ctx)SDFExternalSign_ECC(sessionHandle SessionHandleType,uiAlgID uint,uiDataLength uint)(core.ECCrefPrivateKey,[]byte,core.ECCSignature,error) {
	var err C.SGD_RV
	var pucPrivateKey C.ECCrefPrivateKey
	var pucData C.SGD_UCHAR_PRT
	var pucSignature C.ECCSignature
	err = C.ExternalSign_ECC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiAlgID), &pucPrivateKey, &pucData, C.SGD_UINT32(uiDataLength), &pucSignature)
	privateKey := core.ECCrefPrivateKey{
		Bits: uint(pucPrivateKey.bits),
		K: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.K[0]), 256)), " "),
	}
	signature :=core.ECCSignature{
		R: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSignature.r[0]), 256)), " "),
		S: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSignature.s[0]), 256)), " "),
	}
	data:= C.GoBytes(unsafe.Pointer(pucData), C.int(uiDataLength))
	C.free(unsafe.Pointer(pucData))
	return privateKey,data,signature,ToError(err)

}

func (c *Ctx)SDFExternalDecrypt_ECC(sessionHandle SessionHandleType,uiAlgID uint)(core.ECCrefPrivateKey,core.ECCCipher,[]byte,error){
	var err C.SGD_RV
	var pucPrivateKey C.ECCrefPrivateKey
	var pucEncData C.ECCCipher
	var pucData C.SGD_UCHAR_PRT
	var puiDataLength C.SGD_UINT32
	err = C.ExternalDecrypt_ECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiAlgID), &pucPrivateKey,&pucEncData,&pucData,&puiDataLength)
	privateKey := core.ECCrefPrivateKey{
		Bits: uint(pucPrivateKey.bits),
		K: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.K[0]), 256)), " "),
	}
	encData :=core.ECCCipher{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncData.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncData.y[0]), 256)), " "),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncData.M[0]), 256)), " "),
		L: uint(pucEncData.L),
		C: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncData.C[0]), 256)), " "),
	}
	data:= C.GoBytes(unsafe.Pointer(pucData), C.int(puiDataLength))
	C.free(unsafe.Pointer(pucData))
	return privateKey,encData,data,ToError(err)
}


func (c *Ctx)SDFInternalDecrypt_ECC(sessionHandle SessionHandleType,uiISKIndex uint,uiAlgID uint)(core.ECCCipher,[]byte,error){
	var err C.SGD_RV
	var pucEncData C.ECCCipher
	var pucData C.SGD_UCHAR_PRT
	var puiDataLength C.SGD_UINT32
	err = C.InternalDecrypt_ECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiISKIndex),C.SGD_UINT32(uiAlgID),&pucEncData,&pucData,&puiDataLength)
	encData :=core.ECCCipher{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncData.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncData.y[0]), 256)), " "),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncData.M[0]), 256)), " "),
		L: uint(pucEncData.L),
		C: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncData.C[0]), 256)), " "),
	}
	data:= C.GoBytes(unsafe.Pointer(pucData), C.int(puiDataLength))
	C.free(unsafe.Pointer(pucData))
	return encData,data,ToError(err)
}

func (c *Ctx)SDFInternalEncrypt_ECC(sessionHandle SessionHandleType,uiISKIndex uint,uiAlgID uint,uiDataLength uint)([]byte,core.ECCCipher,error){
	var err C.SGD_RV
	var pucEncData C.ECCCipher
	var pucData C.SGD_UCHAR_PRT
	var puiDataLength C.SGD_UINT32
	err = C.InternalEncrypt_ECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiISKIndex),C.SGD_UINT32(uiAlgID),&pucData,C.SGD_UINT32(uiDataLength),&pucEncData)
	encData :=core.ECCCipher{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncData.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncData.y[0]), 256)), " "),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncData.M[0]), 256)), " "),
		L: uint(pucEncData.L),
		C: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucEncData.C[0]), 256)), " "),
	}
	data:= C.GoBytes(unsafe.Pointer(pucData), C.int(puiDataLength))
	C.free(unsafe.Pointer(pucData))
	return data,encData,ToError(err)
}


func (c *Ctx)SDFExportKeyWithEPK_RSA(sessionHandle SessionHandleType,hKeyHandle KeyHandleType)(core.RSArefPublicKey,[]byte,error){
	var err C.SGD_RV
	var pucPublicKey C.RSArefPublicKey
	var pucKey C.SGD_UCHAR_PRT
	var puiKeyLength C.SGD_UINT32
	err = C.ExportKeyWithEPK_RSA(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_HANDLE(hKeyHandle),&pucPublicKey,&pucKey,&puiKeyLength)
	publickey :=core.RSArefPublicKey{
		Bits: uint(pucPublicKey.bits),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.m[0]), 256)), " "),
		E: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.e[0]), 256)), " "),
	}
	key:= C.GoBytes(unsafe.Pointer(pucKey), C.int(puiKeyLength))
	C.free(unsafe.Pointer(pucKey))
	return publickey,key,ToError(err)
}


func (c *Ctx)SDFExportKeyWithEPK_ECC(sessionHandle SessionHandleType,hKeyHandle KeyHandleType,uiAlgID uint)(core.ECCrefPublicKey,core.ECCCipher,error){
	var err C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	var pucKey C.ECCCipher
	err = C.ExportKeyWithEPK_ECC(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_HANDLE(hKeyHandle),C.SGD_UINT32(uiAlgID),&pucPublicKey,&pucKey)
	publicKey := core.ECCrefPublicKey{
		Bits: uint(pucPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.y[0]), 256)), " "),
	}
	key :=core.ECCCipher{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.y[0]), 256)), " "),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.M[0]), 256)), " "),
		L: uint(pucKey.L),
		C: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.C[0]), 256)), " "),
	}
	return publicKey,key,ToError(err)
}

func (c *Ctx)SDFExportKeyWithKEK(sessionHandle SessionHandleType,hKeyHandle KeyHandleType,uiAlgID uint,uiKEKIndex uint)([]byte,error){
	var err C.SGD_RV
	var pucKey C.SGD_UCHAR_PRT
	var puiKeyLength C.SGD_UINT32
	err = C.ExportKeyWithKEK(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_HANDLE(hKeyHandle),C.SGD_UINT32(uiAlgID),C.SGD_UINT32(uiKEKIndex),&pucKey,&puiKeyLength)
	key:= C.GoBytes(unsafe.Pointer(pucKey), C.int(puiKeyLength))
	C.free(unsafe.Pointer(pucKey))
	return key,ToError(err)
}


func (c *Ctx)SDFExportSignMasterPublicKey_SM9(sessionHandle SessionHandleType,uiKeyIndex uint)(core.SM9refSignMasterPublicKey,error){
	var err C.SGD_RV
	var pPublicKey C.SM9refSignMasterPublicKey
	err = C.ExportSignMasterPublicKey_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),&pPublicKey)
	publicKey :=core.SM9refSignMasterPublicKey{
		Bits: uint(pPublicKey.bits),
		Xa: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pPublicKey.xa[0]), 256)), " "),
		Xb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pPublicKey.xb[0]), 256)), " "),
		Ya: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pPublicKey.ya[0]), 256)), " "),
		Yb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pPublicKey.yb[0]), 256)), " "),
	}
	return publicKey,ToError(err)
}

func (c *Ctx)SDFExportEncMasterPublicKey_SM9(sessionHandle SessionHandleType,uiKeyIndex uint)(core.SM9refEncMasterPublicKey,error){
	var err C.SGD_RV
	var pPublicKey C.SM9refEncMasterPublicKey
	err = C.ExportEncMasterPublicKey_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),&pPublicKey)
	publicKey :=core.SM9refEncMasterPublicKey{
		Bits: uint(pPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pPublicKey.y[0]), 256)), " "),
	}
	return publicKey,ToError(err)
}


func (c *Ctx)SDFExportSignMasterKeyPairG_SM9(sessionHandle SessionHandleType,uiKeyIndex uint)([]byte,error){
	var err C.SGD_RV
	var pPairG C.SGD_UCHAR_PRT
	var puiPairGLen C.SGD_UINT32
	err = C.ExportSignMasterKeyPairG_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),&pPairG,&puiPairGLen)
	pairG:= C.GoBytes(unsafe.Pointer(pPairG), C.int(puiPairGLen))
	C.free(unsafe.Pointer(pPairG))
	return pairG,ToError(err)
}


func (c *Ctx)SDFExportEncMasterKeyPairG_SM9(sessionHandle SessionHandleType,uiKeyIndex uint)([]byte,error){
	var err C.SGD_RV
	var pPairG C.SGD_UCHAR_PRT
	var puiPairGLen C.SGD_UINT32
	err = C.ExportEncMasterKeyPairG_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),&pPairG,&puiPairGLen)
	pairG:= C.GoBytes(unsafe.Pointer(pPairG), C.int(puiPairGLen))
	C.free(unsafe.Pointer(pPairG))
	return pairG,ToError(err)
}

func (c *Ctx)SDFImportUserSignPrivateKey_SM9(sessionHandle SessionHandleType,uiKeyIndex uint)(core.SM9refSignUserPrivateKey,error){
	var err C.SGD_RV
	var pUserPrivateKey C.SM9refSignUserPrivateKey
	err = C.ImportUserSignPrivateKey_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),&pUserPrivateKey)
	privateKey:=core.SM9refSignUserPrivateKey{
		Bits: uint(pUserPrivateKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.y[0]), 256)), " "),
	}
	return privateKey,ToError(err)
}


func (c *Ctx)SDFImportUserEncPrivateKey_SM9(sessionHandle SessionHandleType,uiKeyIndex uint)(core.SM9refEncUserPrivateKey,error){
	var err C.SGD_RV
	var pUserPrivateKey C.SM9refEncUserPrivateKey
	err = C.ImportUserEncPrivateKey_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),&pUserPrivateKey)
	privateKey:=core.SM9refEncUserPrivateKey{
		Bits: uint(pUserPrivateKey.bits),
		Xa: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.xa[0]), 256)), " "),
		Xb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.xb[0]), 256)), " "),
		Ya: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.ya[0]), 256)), " "),
		Yb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.yb[0]), 256)), " "),
	}
	return privateKey,ToError(err)
}

func (c *Ctx)SDFGenerateSignUserPrivateKey_SM9(sessionHandle SessionHandleType,uiKeyIndex uint)(core.SM9refSignUserPrivateKey,error){
	var err C.SGD_RV
	var hid C.SGD_UCHAR
	var pucUserID C.SGD_UCHAR_PRT
	var uiUserIDLen C.SGD_UINT32
	var pUserPrivateKey C.SM9refSignUserPrivateKey
	err = C.GenerateSignUserPrivateKey_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),hid,&pucUserID,C.SGD_UINT32(uiUserIDLen),&pUserPrivateKey)
	privateKey:=core.SM9refSignUserPrivateKey{
		Bits: uint(pUserPrivateKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.y[0]), 256)), " "),
	}
	return privateKey,ToError(err)
}


func (c *Ctx)SDFGenerateEncUserPrivateKey_SM9(sessionHandle SessionHandleType,uiKeyIndex uint,uiUserIDLen uint)(core.SM9refEncUserPrivateKey,[]byte,error){
	var err C.SGD_RV
	var hid C.SGD_UCHAR
	var pucUserID C.SGD_UCHAR_PRT
	var pUserPrivateKey C.SM9refEncUserPrivateKey
	err = C.GenerateEncUserPrivateKey_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),hid,&pucUserID,C.SGD_UINT32(uiUserIDLen),&pUserPrivateKey)
	privateKey:=core.SM9refEncUserPrivateKey{
		Bits: uint(pUserPrivateKey.bits),
		Xa: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.xa[0]), 256)), " "),
		Xb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.xb[0]), 256)), " "),
		Ya: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.ya[0]), 256)), " "),
		Yb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.yb[0]), 256)), " "),
	}
	userID:= C.GoBytes(unsafe.Pointer(pucUserID), C.int(uiUserIDLen))
	C.free(unsafe.Pointer(pucUserID))
	return privateKey,userID,ToError(err)
}


func (c *Ctx)SDFSign_SM9(sessionHandle SessionHandleType,uiKeyIndex uint)(core.SM9refSignUserPrivateKey,core.SM9refSignMasterPublicKey,[]byte,core.SM9Signature,error){
	var err C.SGD_RV
	var pUserPrivateKey C.SM9refSignUserPrivateKey
	var pMasterPublicKey C.SM9refSignMasterPublicKey
	var pucDataInput C.SGD_UCHAR_PRT
	var uiDataInputLen C.SGD_UINT32
	var pSignature C.SM9Signature
	err = C.Sign_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),&pUserPrivateKey,&pMasterPublicKey,&pucDataInput,uiDataInputLen,&pSignature)
	privateKey := core.SM9refSignUserPrivateKey{
		Bits: uint(pUserPrivateKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.y[0]), 256)), " "),
	}
	publicKey := core.SM9refSignMasterPublicKey{
		Bits: uint(pMasterPublicKey.bits),
		Xa: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pMasterPublicKey.xa[0]), 256)), " "),
		Xb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pMasterPublicKey.xb[0]), 256)), " "),
		Ya: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pMasterPublicKey.ya[0]), 256)), " "),
		Yb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pMasterPublicKey.yb[0]), 256)), " "),
	}
	sign:=core.SM9Signature{
		H: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pSignature.h[0]), 256)), " "),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pSignature.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pSignature.y[0]), 256)), " "),
	}
	dataInput:= C.GoBytes(unsafe.Pointer(pucDataInput), C.int(uiDataInputLen))
	C.free(unsafe.Pointer(pucDataInput))
	return privateKey,publicKey,dataInput,sign,ToError(err)
}

func (c *Ctx)SDFSignEx_SM9(sessionHandle SessionHandleType,uiKeyIndex uint,uiPairGLen uint,uiDataInputLen uint)(core.SM9refSignUserPrivateKey,core.SM9refSignMasterPublicKey,[]byte,[]byte,core.SM9Signature,error){
	var err C.SGD_RV
	var pUserPrivateKey C.SM9refSignUserPrivateKey
	var pMasterPublicKey C.SM9refSignMasterPublicKey
	var pPairG C.SGD_UCHAR_PRT
	var pucDataInput C.SGD_UCHAR_PRT
	var pSignature C.SM9Signature
	err = C.SignEx_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyIndex),&pUserPrivateKey,&pMasterPublicKey,&pPairG,C.SGD_UINT32(uiPairGLen),&pucDataInput,C.SGD_UINT32(uiDataInputLen),&pSignature)
	privateKey := core.SM9refSignUserPrivateKey{
		Bits: uint(pUserPrivateKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.y[0]), 256)), " "),
	}
	publicKey := core.SM9refSignMasterPublicKey{
		Bits: uint(pMasterPublicKey.bits),
		Xa: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pMasterPublicKey.xa[0]), 256)), " "),
		Xb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pMasterPublicKey.xb[0]), 256)), " "),
		Ya: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pMasterPublicKey.ya[0]), 256)), " "),
		Yb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pMasterPublicKey.yb[0]), 256)), " "),
	}
	sign:=core.SM9Signature{
		H: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pSignature.h[0]), 256)), " "),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pSignature.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pSignature.y[0]), 256)), " "),
	}
	pairGLen:= C.GoBytes(unsafe.Pointer(pPairG), C.int(uiPairGLen))
	C.free(unsafe.Pointer(pPairG))
	dataInput:= C.GoBytes(unsafe.Pointer(pucDataInput), C.int(uiDataInputLen))
	C.free(unsafe.Pointer(pucDataInput))
	return privateKey,publicKey,dataInput,pairGLen,sign,ToError(err)
}


func (c *Ctx)SDFVerify_SM9(sessionHandle SessionHandleType,uiUserIDLen uint,uiDataInputLen uint)(core.SM9refSignMasterPublicKey,[]byte,[]byte,core.SM9Signature,error){
	var err C.SGD_RV
	var hid C.SGD_UCHAR
	var pucUserID C.SGD_UCHAR_PRT
	var pMasterPublicKey C.SM9refSignMasterPublicKey
	var pucData C.SGD_UCHAR_PRT
	var pSignature C.SM9Signature
	err = C.Verify_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),hid,&pucUserID,C.SGD_UINT32(uiUserIDLen),&pMasterPublicKey,&pucData,C.SGD_UINT32(uiDataInputLen),&pSignature)
	publicKey := core.SM9refSignMasterPublicKey{
		Bits: uint(pMasterPublicKey.bits),
		Xa: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pMasterPublicKey.xa[0]), 256)), " "),
		Xb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pMasterPublicKey.xb[0]), 256)), " "),
		Ya: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pMasterPublicKey.ya[0]), 256)), " "),
		Yb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pMasterPublicKey.yb[0]), 256)), " "),
	}
	sign:=core.SM9Signature{
		H: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pSignature.h[0]), 256)), " "),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pSignature.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pSignature.y[0]), 256)), " "),
	}
	userIDLen:= C.GoBytes(unsafe.Pointer(pucUserID), C.int(uiUserIDLen))
	C.free(unsafe.Pointer(pucUserID))
	data := C.GoBytes(unsafe.Pointer(pucData), C.int(uiDataInputLen))
	C.free(unsafe.Pointer(pucUserID))
	return publicKey,userIDLen,data,sign,ToError(err)
}

func (c *Ctx)SDFVerifyEx_SM9(sessionHandle SessionHandleType,uiUserIDLen uint,uiPairGLen uint,uiDataInputLen uint)(core.SM9refSignMasterPublicKey,[]byte,[]byte,[]byte,core.SM9Signature,error){
	var err C.SGD_RV
	var hid C.SGD_UCHAR
	var pucUserID C.SGD_UCHAR_PRT
	var pMasterPublicKey C.SM9refSignMasterPublicKey
	var pPairG C.SGD_UCHAR_PRT
	var pucData C.SGD_UCHAR_PRT
	var pSignature C.SM9Signature
	err = C.VerifyEx_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),hid,&pucUserID,C.SGD_UINT32(uiUserIDLen),&pMasterPublicKey,&pPairG,C.SGD_UINT32(uiPairGLen),&pucData,C.SGD_UINT32(uiDataInputLen),&pSignature)
	publicKey := core.SM9refSignMasterPublicKey{
		Bits: uint(pMasterPublicKey.bits),
		Xa: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pMasterPublicKey.xa[0]), 256)), " "),
		Xb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pMasterPublicKey.xb[0]), 256)), " "),
		Ya: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pMasterPublicKey.ya[0]), 256)), " "),
		Yb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pMasterPublicKey.yb[0]), 256)), " "),
	}
	sign:=core.SM9Signature{
		H: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pSignature.h[0]), 256)), " "),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pSignature.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pSignature.y[0]), 256)), " "),
	}
	userIDLen:= C.GoBytes(unsafe.Pointer(pucUserID), C.int(uiUserIDLen))
	C.free(unsafe.Pointer(pucUserID))
	pairG:= C.GoBytes(unsafe.Pointer(pPairG), C.int(uiPairGLen))
	C.free(unsafe.Pointer(pPairG))
	data := C.GoBytes(unsafe.Pointer(pucData), C.int(uiDataInputLen))
	C.free(unsafe.Pointer(pucUserID))
	return publicKey,userIDLen,pairG,data,sign,ToError(err)
}


func (c *Ctx)SDFEncrypt_SM9(sessionHandle SessionHandleType,uiUserIDLen uint,uiDataInputLen uint,uiPairGLen uint)(core.SM9refEncMasterPublicKey,[]byte,[]byte,core.SM9Cipher,error){
	var err C.SGD_RV
	var hid C.SGD_UCHAR
	var pucUserID C.SGD_UCHAR_PRT
	var pPubluicKey C.SM9refEncMasterPublicKey
	var pucData C.SGD_UCHAR_PRT
	var pCipher C.SM9Cipher
	err = C.Encrypt_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),hid,&pucUserID,C.SGD_UINT32(uiUserIDLen),&pPubluicKey,&pucData,C.SGD_UINT32(uiDataInputLen),&pCipher)
	publicKey := core.SM9refEncMasterPublicKey{
		Bits: uint(pPubluicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pPubluicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pPubluicKey.y[0]), 256)), " "),
	}
	cipher:=core.SM9Cipher{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pCipher.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pCipher.y[0]), 256)), " "),
		H: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pCipher.h[0]), 256)), " "),
		L: uint(pCipher.L),
		C: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pCipher.C[0]), 256)), " "),
	}
	userIDLen:= C.GoBytes(unsafe.Pointer(pucUserID), C.int(uiUserIDLen))
	C.free(unsafe.Pointer(pucUserID))
	data := C.GoBytes(unsafe.Pointer(pucData), C.int(uiDataInputLen))
	C.free(unsafe.Pointer(pucUserID))
	return publicKey,userIDLen,data,cipher,ToError(err)
}


func (c *Ctx)SDFEncryptEx_SM9(sessionHandle SessionHandleType,uiUserIDLen uint,uiDataInputLen uint,nPairGLen uint)(core.SM9refEncMasterPublicKey,[]byte,[]byte,[]byte,core.SM9Cipher,error){
	var err C.SGD_RV
	var hid C.SGD_UCHAR
	var pucUserID C.SGD_UCHAR_PRT
	var pPubluicKey C.SM9refEncMasterPublicKey
	var pPairG C.SGD_UCHAR_PRT
	var pucData C.SGD_UCHAR_PRT
	var pCipher C.SM9Cipher
	err = C.EncryptEx_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),hid,&pucUserID,C.SGD_UINT32(uiUserIDLen),&pPubluicKey,&pPairG,C.SGD_UINT32(nPairGLen),&pucData,C.SGD_UINT32(uiDataInputLen),&pCipher)
	publicKey := core.SM9refEncMasterPublicKey{
		Bits: uint(pPubluicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pPubluicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pPubluicKey.y[0]), 256)), " "),
	}
	cipher:=core.SM9Cipher{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pCipher.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pCipher.y[0]), 256)), " "),
		H: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pCipher.h[0]), 256)), " "),
		L: uint(pCipher.L),
		C: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pCipher.C[0]), 256)), " "),
	}
	userID:= C.GoBytes(unsafe.Pointer(pucUserID), C.int(uiUserIDLen))
	C.free(unsafe.Pointer(pucUserID))
	pairG := C.GoBytes(unsafe.Pointer(pPairG), C.int(nPairGLen))
	C.free(unsafe.Pointer(pPairG))
	data := C.GoBytes(unsafe.Pointer(pucData), C.int(uiDataInputLen))
	C.free(unsafe.Pointer(pucData))
	return publicKey,userID,pairG,data,cipher,ToError(err)
}

func (c *Ctx)SDFDecrypt_SM9(sessionHandle SessionHandleType,uiUserIDLen uint,uiKeyIndex uint)([]byte,core.SM9refEncUserPrivateKey,core.SM9Cipher,[]byte,error){
	var err C.SGD_RV
	var pucUserID C.SGD_UCHAR_PRT
	var pUserPrivateKey C.SM9refEncUserPrivateKey
	var pCipher C.SM9Cipher
	var pucPlainData C.SGD_UCHAR_PRT
	var uiPlainDataLength C.SGD_UINT32
	err = C.Decrypt_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),&pucUserID,C.SGD_UINT32(uiUserIDLen),C.SGD_UINT32(uiKeyIndex),&pUserPrivateKey,&pCipher,&pucPlainData,&uiPlainDataLength)
	userPrivateKey := core.SM9refEncUserPrivateKey{
		Bits: uint(pUserPrivateKey.bits),
		Xa: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.xa[0]), 256)), " "),
		Xb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.xb[0]), 256)), " "),
		Ya: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.ya[0]), 256)), " "),
		Yb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.yb[0]), 256)), " "),
	}
	cipher:=core.SM9Cipher{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pCipher.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pCipher.y[0]), 256)), " "),
		H: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pCipher.h[0]), 256)), " "),
		L: uint(pCipher.L),
		C: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pCipher.C[0]), 256)), " "),
	}
	userID:= C.GoBytes(unsafe.Pointer(pucUserID), C.int(uiUserIDLen))
	C.free(unsafe.Pointer(pucUserID))
    plainData:= C.GoBytes(unsafe.Pointer(pucPlainData), C.int(uiPlainDataLength))
	C.free(unsafe.Pointer(pucPlainData))
	return userID,userPrivateKey,cipher,plainData,ToError(err)
}

func (c *Ctx)SDFEncap_SM9(sessionHandle SessionHandleType,uiUserIDLen uint,uiKeyLen uint)([]byte,core.SM9refEncMasterPublicKey,[]byte,core.SM9refKeyPackage,error){
	var err C.SGD_RV
	var hid C.SGD_UCHAR
	var pucUserID C.SGD_UCHAR_PRT
	var pPublicKey C.SM9refEncMasterPublicKey
	var pKey C.SGD_UCHAR_PRT
	var pKeyPackage C.SM9refKeyPackage
	err = C.Encap_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),hid,&pucUserID,C.SGD_UINT32(uiUserIDLen),&pPublicKey,C.SGD_UINT32(uiKeyLen),&pKey,&pKeyPackage)
	publicKey :=core.SM9refEncMasterPublicKey{
		Bits: uint(pPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pPublicKey.y[0]), 256)), " "),
	}
	keyPackage:=core.SM9refKeyPackage{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pKeyPackage.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pKeyPackage.y[0]), 256)), " "),
	}
	userID:= C.GoBytes(unsafe.Pointer(pucUserID), C.int(uiUserIDLen))
	C.free(unsafe.Pointer(pucUserID))
	key:= C.GoBytes(unsafe.Pointer(pKey), C.int(uiKeyLen))
	C.free(unsafe.Pointer(pKey))
	return userID,publicKey,key,keyPackage,ToError(err)
}

func (c *Ctx)SDFDecap_SM9(sessionHandle SessionHandleType,uiUserIDLen uint,uiKeyIndex uint,uiKeyLen uint)([]byte,core.SM9refEncUserPrivateKey,core.SM9refKeyPackage,[]byte,error){
	var err C.SGD_RV
	var pucUserID C.SGD_UCHAR_PRT
	var pUserPrivateKey C.SM9refEncUserPrivateKey
	var pKeyPackage C.SM9refKeyPackage
	var pucKey C.SGD_UCHAR_PRT
	err = C.Decap_SM9(c.libHandle,C.SGD_HANDLE(sessionHandle),&pucUserID,C.SGD_UINT32(uiUserIDLen),C.SGD_UINT32(uiKeyIndex),&pUserPrivateKey,&pKeyPackage,C.SGD_UINT32(uiKeyLen),&pucKey)
	privateKey:=core.SM9refEncUserPrivateKey{
		Bits: uint(pUserPrivateKey.bits),
		Xa: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.xa[0]), 256)), " "),
		Xb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.xb[0]), 256)), " "),
		Ya: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.ya[0]), 256)), " "),
		Yb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pUserPrivateKey.yb[0]), 256)), " "),
	}
	keyPackage:=core.SM9refKeyPackage{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pKeyPackage.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pKeyPackage.y[0]), 256)), " "),
	}
	userID:= C.GoBytes(unsafe.Pointer(pucUserID), C.int(uiUserIDLen))
	C.free(unsafe.Pointer(pucUserID))
	key:= C.GoBytes(unsafe.Pointer(pucKey), C.int(uiKeyLen))
	C.free(unsafe.Pointer(pucKey))
	return userID,privateKey,keyPackage,key,ToError(err)
}


func (c *Ctx)SDFGenerateAgreementDataWithSM9(sessionHandle SessionHandleType,uiResponseIDLength uint)([]byte,core.SM9refEncMasterPublicKey,core.SM9refEncMasterPublicKey,AgreementHandleType,error){
	var err C.SGD_RV
	var hid C.SGD_UCHAR
	var pucResponseID C.SGD_UCHAR_PRT
	var pPublicKey C.SM9refEncMasterPublicKey
	var pucSponsorTmpPublicKey C.SM9refEncMasterPublicKey
	var phAgreementHandle C.SGD_HANDLE
	err = C.GenerateAgreementDataWithSM9(c.libHandle,C.SGD_HANDLE(sessionHandle),hid,&pucResponseID,C.SGD_UINT32(uiResponseIDLength),&pPublicKey,&pucSponsorTmpPublicKey,&phAgreementHandle)
	publicKey:=core.SM9refEncMasterPublicKey{
		Bits: uint(pPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pPublicKey.y[0]), 256)), " "),
	}
	sponsorTmpPublicKey:=core.SM9refEncMasterPublicKey{
		Bits: uint(pucSponsorTmpPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSponsorTmpPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSponsorTmpPublicKey.y[0]), 256)), " "),
	}

	responseID:= C.GoBytes(unsafe.Pointer(pucResponseID), C.int(uiResponseIDLength))
	C.free(unsafe.Pointer(pucResponseID))
	return responseID,publicKey,sponsorTmpPublicKey,AgreementHandleType(phAgreementHandle),ToError(err)
}


func (c *Ctx)SDFGenerateAgreemetDataAndKeyWithSM9(sessionHandle SessionHandleType,uiKeyLen uint,uiResponseIDLen uint,uiSponsorIDLen uint,uiKeyIndex uint)([]byte,[]byte,core.SM9refEncUserPrivateKey,core.SM9refEncMasterPublicKey,core.SM9refEncMasterPublicKey,core.SM9refEncMasterPublicKey,[]byte,[]byte,KeyHandleType,error){
	var err C.SGD_RV
	var hid C.SGD_UCHAR
	var pucResponseID C.SGD_UCHAR_PRT
	var pucSponsorID C.SGD_UCHAR_PRT
	var pucResponsePrivateKey C.SM9refEncUserPrivateKey
	var pucPublicKey C.SM9refEncMasterPublicKey
	var pucSponsorTmpPublicKey C.SM9refEncMasterPublicKey
	var pucResponseTmpPublicKey C.SM9refEncMasterPublicKey
	var pucHashSB C.SGD_UCHAR_PRT
	var pucHashS2 C.SGD_UCHAR_PRT
	var puiSBLen C.SGD_UINT32
	var puiS2Len C.SGD_UINT32
	var phKeyHandle C.SGD_HANDLE
	err = C.GenerateAgreemetDataAndKeyWithSM9(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyLen),hid,&pucResponseID,C.SGD_UINT32(uiResponseIDLen),&pucSponsorID,C.SGD_UINT32(uiSponsorIDLen),C.SGD_UINT32(uiKeyIndex),&pucResponsePrivateKey,&pucPublicKey,&pucSponsorTmpPublicKey,&pucResponseTmpPublicKey,&pucHashSB,&puiSBLen,&pucHashS2,&puiS2Len,&phKeyHandle)
	privateKey:=core.SM9refEncUserPrivateKey{
		Bits: uint(pucResponsePrivateKey.bits),
		Xa: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucResponsePrivateKey.xa[0]), 256)), " "),
		Xb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucResponsePrivateKey.xb[0]), 256)), " "),
		Ya: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucResponsePrivateKey.ya[0]), 256)), " "),
		Yb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucResponsePrivateKey.yb[0]), 256)), " "),
	}
	publicKey:=core.SM9refEncMasterPublicKey{
		Bits: uint(pucPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.y[0]), 256)), " "),
	}

	sponsorTmpPublicKey:=core.SM9refEncMasterPublicKey{
		Bits: uint(pucSponsorTmpPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSponsorTmpPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSponsorTmpPublicKey.y[0]), 256)), " "),
	}
	responseTmpPublicKey:=core.SM9refEncMasterPublicKey{
		Bits: uint(pucResponseTmpPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucResponseTmpPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucResponseTmpPublicKey.y[0]), 256)), " "),
	}

	responseID:= C.GoBytes(unsafe.Pointer(pucResponseID), C.int(uiResponseIDLen))
	C.free(unsafe.Pointer(pucResponseID))
	sponsorID:= C.GoBytes(unsafe.Pointer(pucSponsorID), C.int(uiSponsorIDLen))
	C.free(unsafe.Pointer(pucSponsorID))
	hashSB:= C.GoBytes(unsafe.Pointer(pucHashSB), C.int(uiResponseIDLen))
	C.free(unsafe.Pointer(pucHashSB))
	hashS2:= C.GoBytes(unsafe.Pointer(pucHashS2), C.int(uiSponsorIDLen))
	C.free(unsafe.Pointer(pucHashS2))
	return responseID,sponsorID,privateKey,publicKey,sponsorTmpPublicKey,responseTmpPublicKey,hashSB,hashS2,KeyHandleType(phKeyHandle),ToError(err)
}

func (c *Ctx)SDFGenerateKeyWithSM9(sessionHandle SessionHandleType,uiKeyLen uint,uiSponsorIDLen uint,uiResponseIDLen uint,uiKeyIndex uint,uiSBLen uint,hAgreementHandle  AgreementHandleType)([]byte,[]byte,core.SM9refEncUserPrivateKey,core.SM9refEncMasterPublicKey,core.SM9refEncMasterPublicKey,[]byte,[]byte,KeyHandleType,error){
	var err C.SGD_RV
	var hid C.SGD_UCHAR
	var pucSponsorID C.SGD_UCHAR_PRT
	var pucResponseID C.SGD_UCHAR_PRT
	var pucSponsorPrivateKey C.SM9refEncUserPrivateKey
	var pucPublicKey C.SM9refEncMasterPublicKey
	var pucResponseTmpPublicKey C.SM9refEncMasterPublicKey
	var pucHashSB C.SGD_UCHAR_PRT
	var pucHashSA C.SGD_UCHAR_PRT
	var puiSALen C.SGD_UINT32
	var phKeyHandle C.SGD_HANDLE
	err = C.GenerateKeyWithSM9(c.libHandle,C.SGD_HANDLE(sessionHandle),C.SGD_UINT32(uiKeyLen),hid,&pucSponsorID,C.SGD_UINT32(uiSponsorIDLen),&pucResponseID,C.SGD_UINT32(uiResponseIDLen),C.SGD_UINT32(uiKeyIndex),&pucSponsorPrivateKey,&pucPublicKey,&pucResponseTmpPublicKey,&pucHashSB,C.SGD_UINT32(uiSBLen),&pucHashSA,&puiSALen,C.SGD_HANDLE(hAgreementHandle),&phKeyHandle)
	privateKey:=core.SM9refEncUserPrivateKey{
		Bits: uint(pucSponsorPrivateKey.bits),
		Xa: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSponsorPrivateKey.xa[0]), 256)), " "),
		Xb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSponsorPrivateKey.xb[0]), 256)), " "),
		Ya: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSponsorPrivateKey.ya[0]), 256)), " "),
		Yb: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSponsorPrivateKey.yb[0]), 256)), " "),
	}
	publicKey:=core.SM9refEncMasterPublicKey{
		Bits: uint(pucPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.y[0]), 256)), " "),
	}
	responseTmpPublicKey:=core.SM9refEncMasterPublicKey{
		Bits: uint(pucResponseTmpPublicKey.bits),
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucResponseTmpPublicKey.x[0]), 256)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucResponseTmpPublicKey.y[0]), 256)), " "),
	}
	sponsorID:= C.GoBytes(unsafe.Pointer(pucSponsorID), C.int(uiSponsorIDLen))
	C.free(unsafe.Pointer(pucSponsorID))
	responseID:= C.GoBytes(unsafe.Pointer(pucResponseID), C.int(uiResponseIDLen))
	C.free(unsafe.Pointer(pucResponseID))
	hashSB:= C.GoBytes(unsafe.Pointer(pucHashSB), C.int(uiSBLen))
	C.free(unsafe.Pointer(pucHashSB))
	hashSA:= C.GoBytes(unsafe.Pointer(pucHashSA), C.int(puiSALen))
	C.free(unsafe.Pointer(pucHashSA))
	return sponsorID,responseID,privateKey,publicKey,responseTmpPublicKey,hashSB,hashSA,KeyHandleType(phKeyHandle),ToError(err)
}

func (c *Ctx)SDFGenerateKeyVerifySM9(sessionHandle SessionHandleType,uiS2Len uint,uiSALen uint)([]byte,[]byte,error){
	var err C.SGD_RV
	var pHashS2 C.SGD_UCHAR_PRT
	var pHashSA C.SGD_UCHAR_PRT
	err = C.GenerateKeyVerifySM9(c.libHandle,C.SGD_HANDLE(sessionHandle),&pHashS2,C.SGD_UINT32(uiS2Len),&pHashSA,C.SGD_UINT32(uiSALen))
	hashS2:= C.GoBytes(unsafe.Pointer(pHashS2), C.int(uiS2Len))
	C.free(unsafe.Pointer(pHashS2))
	hashSA:= C.GoBytes(unsafe.Pointer(pHashSA), C.int(uiSALen))
	C.free(unsafe.Pointer(pHashSA))
	return hashS2,hashSA,ToError(err)
}