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


typedef unsigned char*    SGD_UCHAR_PRT;

#ifdef _WIN32
#include<windows.h>
// duplicated LibHandle section
struct LibHandle {
	HMODULE handle;
};

#else
#include <dlfcn.h>

struct LibHandle {
	void *handle;
};

#endif

//53. EPK方式导出RSA密钥
SGD_RV SDFExportKeyWithEPK_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, RSArefPublicKey *pucPublicKey, SGD_UCHAR_PRT *pucKey, SGD_UINT32 *puiKeyLength)
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

//30. 外部公钥RSA运算
SGD_RV SDFExternalPublicKeyOperation_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, RSArefPublicKey *pucPublicKey,SGD_UCHAR_PRT pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR_PRT *pucDataOutput,SGD_UINT32  *puiOutputLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , RSArefPublicKey *,SGD_UCHAR *,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32  *);
	*pucDataOutput = calloc(*puiOutputLength, sizeof(SGD_UCHAR));
	if (*pucDataOutput == NULL) {
		return SGD_FALSE;
	}
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExternalPublicKeyOperation_RSA");
	return (*fptr)(hSessionHandle,  pucPublicKey, pucDataInput,  uiInputLength, *pucDataOutput,  puiOutputLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExternalPublicKeyOperation_RSA");
	return (*fptr)(hSessionHandle,  pucPublicKey, pucDataInput,  uiInputLength, *pucDataOutput,  puiOutputLength);
#endif
}
//31. 外部私钥RSA运算
SGD_RV SDFExternalPrivateKeyOperation_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle, RSArefPrivateKey *pucPrivateKey,SGD_UCHAR_PRT pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR_PRT *pucDataOutput,SGD_UINT32  *puiOutputLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE , RSArefPrivateKey *,SGD_UCHAR *,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32  *);
	*pucDataOutput = calloc(*puiOutputLength, sizeof(SGD_UCHAR));
	if (*pucDataOutput == NULL) {
		return SGD_FALSE;
	}
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ExternalPrivateKeyOperation_RSA");
	return (*fptr)(hSessionHandle,  pucPrivateKey, pucDataInput,  uiInputLength, *pucDataOutput,  puiOutputLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ExternalPrivateKeyOperation_RSA");
	return (*fptr)(hSessionHandle,  pucPrivateKey, pucDataInput,  uiInputLength, *pucDataOutput,  puiOutputLength);
#endif
}
//32. 内部公钥RSA运算
SGD_RV SDFInternalPublicKeyOperation_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SGD_UCHAR_PRT pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR_PRT *pucDataOutput,SGD_UINT32  *puiOutputLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32  *);
    *pucDataOutput = calloc(*puiOutputLength, sizeof(SGD_UCHAR));
	if (*pucDataOutput == NULL) {
		return SGD_FALSE;
	}
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_InternalPublicKeyOperation_RSA");
	return (*fptr)(hSessionHandle,  uiKeyIndex, pucDataInput,  uiInputLength, *pucDataOutput,  puiOutputLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_InternalPublicKeyOperation_RSA");
	return (*fptr)(hSessionHandle,  uiKeyIndex, pucDataInput,  uiInputLength, *pucDataOutput,  puiOutputLength);
#endif
}
//33. 内部私RSA运算
SGD_RV SDFInternalPrivateKeyOperation_RSA(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SGD_UCHAR_PRT pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR_PRT *pucDataOutput,SGD_UINT32  *puiOutputLength)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32  ,SGD_UCHAR *,SGD_UINT32  *);
    *pucDataOutput = calloc(*puiOutputLength, sizeof(SGD_UCHAR));
	if (*pucDataOutput == NULL) {
		return SGD_FALSE;
	}
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_InternalPrivateKeyOperation_RSA");
	return (*fptr)(hSessionHandle,  uiKeyIndex, pucDataInput,uiInputLength,*pucDataOutput,puiOutputLength);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_InternalPrivateKeyOperation_RSA");
	return (*fptr)(hSessionHandle,  uiKeyIndex, pucDataInput,uiInputLength,*pucDataOutput,puiOutputLength);
#endif
}
*/
import "C"
import "unsafe"

// SDFExternalPublicKeyOperation_RSA 30.外部公钥 RSA 运算
func (c *Ctx) SDFExternalPublicKeyOperation_RSA(sessionHandle SessionHandleType, publicKey RSArefPublicKey, dataInput []byte, uiInputLength uint) (dataOutput []byte, err error) {
	var err1 C.SGD_RV
	var pucDataOutput C.SGD_UCHAR_PRT
	var puiOutputLength C.SGD_UINT32
	pucPublicKey := ConvertToRSArefPublicKeyC(publicKey)
	err1 = C.SDFExternalPublicKeyOperation_RSA(c.libHandle, C.SGD_HANDLE(sessionHandle), &pucPublicKey, CMessage(dataInput), C.SGD_UINT32(uiInputLength), &pucDataOutput, &puiOutputLength)
	dataOutput = C.GoBytes(unsafe.Pointer(pucDataOutput), C.int(puiOutputLength))
	C.free(unsafe.Pointer(pucDataOutput))
	err = ToError(err1)
	return dataOutput, err
}

// SDFExternalPrivateKeyOperation_RSA 31. 外部私钥RSA运算
func (c *Ctx) SDFExternalPrivateKeyOperation_RSA(sessionHandle SessionHandleType, privateKey RSArefPrivateKey, dataInput []byte, uiInputLength uint) (dataOutput []byte, err error) {
	var err1 C.SGD_RV
	var pucDataOutput C.SGD_UCHAR_PRT
	var puiOutputLength C.SGD_UINT32
	pucPrivateKey := ConvertToRSArefPrivateKeyC(privateKey)
	err1 = C.SDFExternalPrivateKeyOperation_RSA(c.libHandle, C.SGD_HANDLE(sessionHandle), &pucPrivateKey, CMessage(dataInput), C.SGD_UINT32(uiInputLength), &pucDataOutput, &puiOutputLength)
	dataOutput = C.GoBytes(unsafe.Pointer(pucDataOutput), C.int(puiOutputLength))
	C.free(unsafe.Pointer(pucDataOutput))
	err = ToError(err1)
	return dataOutput, err
}

// SDFInternalPublicKeyOperation_RSA 32.内部公钥 RSA 运算
func (c *Ctx) SDFInternalPublicKeyOperation_RSA(sessionHandle SessionHandleType, uiKeyIndex uint, pucDataInput []byte, uiInputLength uint) (dataOutput []byte, err error) {
	var err1 C.SGD_RV
	var pucDataOutput C.SGD_UCHAR_PRT
	var puiOutputLength C.SGD_UINT32
	err1 = C.SDFInternalPublicKeyOperation_RSA(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyIndex), CMessage(pucDataInput), C.SGD_UINT32(uiInputLength), &pucDataOutput, &puiOutputLength)
	dataOutput = C.GoBytes(unsafe.Pointer(pucDataOutput), C.int(puiOutputLength))
	err = ToError(err1)
	C.free(unsafe.Pointer(pucDataOutput))
	return dataOutput, err
}

// SDFInternalPrivateKeyOperation_RSA 33.外部私钥 RSA 运算
func (c *Ctx) SDFInternalPrivateKeyOperation_RSA(sessionHandle SessionHandleType, uiKeyIndex uint, inData []byte, uiInputLength uint) (dataOutput []byte, err error) {
	var err1 C.SGD_RV
	var pucDataOutput C.SGD_UCHAR_PRT
	var puiOutputLength C.SGD_UINT32
	err1 = C.SDFInternalPrivateKeyOperation_RSA(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyIndex), CMessage(inData), C.SGD_UINT32(uiInputLength), &pucDataOutput, &puiOutputLength)
	dataOutput1 := C.GoBytes(unsafe.Pointer(pucDataOutput), C.int(puiOutputLength))
	dataOutput = deepCopy(dataOutput1)
	C.free(unsafe.Pointer(pucDataOutput))
	err = ToError(err1)
	return dataOutput, err
}

// SDFExportKeyWithEPK_RSA 53. EPK方式导出RSA密钥
func (c *Ctx) SDFExportKeyWithEPK_RSA(sessionHandle SessionHandleType, hKeyHandle KeyHandleType, publicKey RSArefPublicKey) (key []byte, err error) {
	var err1 C.SGD_RV
	pucPublicKey := ConvertToRSArefPublicKeyC(publicKey)
	var pucKey C.SGD_UCHAR_PRT
	var puiKeyLength C.SGD_UINT32
	err1 = C.SDFExportKeyWithEPK_RSA(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_HANDLE(hKeyHandle), &pucPublicKey, &pucKey, &puiKeyLength)
	key = C.GoBytes(unsafe.Pointer(pucKey), C.int(puiKeyLength))
	C.free(unsafe.Pointer(pucKey))
	err = ToError(err1)
	return key, err
}
