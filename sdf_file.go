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

#endif
//46. 创建文件
SGD_RV SDFCreateFile(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiFileSize)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_UCHAR *,SGD_UINT32 ,SGD_UINT32 );
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_CreateFile");
	return (*fptr)(hSessionHandle, pucFileName, uiNameLen, uiFileSize);
#else

	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_CreateFile");
	return (*fptr)(hSessionHandle, pucFileName, uiNameLen, uiFileSize);

#endif
}
//47. 读取文件
SGD_RV SDFReadFile(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiOffset,SGD_UINT32 *puiReadLength,SGD_UCHAR_PRT *pucBuffer)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UCHAR *,SGD_UINT32 ,SGD_UINT32 ,SGD_UINT32 *,SGD_UCHAR *);
	*pucBuffer = calloc(*puiReadLength, sizeof(SGD_UCHAR));
	if (*pucBuffer == NULL) {
		return SGD_FALSE;
	}
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_ReadFile");
	return (*fptr)(hSessionHandle, pucFileName, uiNameLen, uiOffset, puiReadLength, *pucBuffer);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_ReadFile");
	return (*fptr)(hSessionHandle, pucFileName, uiNameLen, uiOffset, puiReadLength, *pucBuffer);
#endif
}
//48. 写文件
SGD_RV SDFWriteFile(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiOffset,SGD_UINT32 uiWriteLength,SGD_UCHAR_PRT pucBuffer)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UCHAR *,SGD_UINT32 ,SGD_UINT32 ,SGD_UINT32 ,SGD_UCHAR *);
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_WriteFile");
	return (*fptr)(hSessionHandle, pucFileName, uiNameLen, uiOffset, uiWriteLength, pucBuffer);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_WriteFile");
	return (*fptr)(hSessionHandle, pucFileName, uiNameLen, uiOffset, uiWriteLength, pucBuffer);
#endif
}
//49. 删除文件
SGD_RV SDFDeleteFile(struct LibHandle * h,SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT pucFileName,SGD_UINT32 uiNameLen)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE ,SGD_UCHAR *,SGD_UINT32 );
#ifdef _WIN32
	FPTR fptr = (FPTR)GetProcAddress(h->handle, "SDF_DeleteFile");
	return (*fptr)(hSessionHandle, pucFileName, uiNameLen);
#else
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_DeleteFile");
	return (*fptr)(hSessionHandle, pucFileName, uiNameLen);
#endif
}
*/
import "C"
import "unsafe"

// SDFCreateFile 46.创建文件
func (c *Ctx) SDFCreateFile(sessionHandle SessionHandleType, fileName []byte, uiFileSize uint) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFCreateFile(c.libHandle, C.SGD_HANDLE(sessionHandle), CMessage(fileName), C.SGD_UINT32(len(fileName)), C.SGD_UINT32(uiFileSize))
	err = ToError(err1)
	return err
}

// SDFReadFile 47.读取文件
func (c *Ctx) SDFReadFile(sessionHandle SessionHandleType, fileName []byte, uiOffset uint, readLength uint) (buffer []byte, readLength1 uint, err error) {
	var err1 C.SGD_RV
	var puiReadLength C.SGD_UINT32
	var pucBuffer C.SGD_UCHAR_PRT
	puiReadLength = C.SGD_UINT32(readLength)
	err1 = C.SDFReadFile(c.libHandle, C.SGD_HANDLE(sessionHandle), CMessage(fileName), C.SGD_UINT32(len(fileName)), C.SGD_UINT32(uiOffset), &puiReadLength, &pucBuffer)
	buffer = C.GoBytes(unsafe.Pointer(pucBuffer), C.int(puiReadLength))
	readLength1 = uint(puiReadLength)
	C.free(unsafe.Pointer(pucBuffer))
	err = ToError(err1)
	return buffer, readLength1, err
}

// SDFWriteFile 48.写文件
func (c *Ctx) SDFWriteFile(sessionHandle SessionHandleType, fileName []byte, uiOffset uint, buffer []byte, bufferLength uint) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFWriteFile(c.libHandle, C.SGD_HANDLE(sessionHandle), CMessage(fileName), C.SGD_UINT32(len(fileName)), C.SGD_UINT32(uiOffset), C.SGD_UINT32(bufferLength), CMessage(buffer))
	err = ToError(err1)
	return err
}

// SDFDeleteFile 49.删除文件
func (c *Ctx) SDFDeleteFile(sessionHandle SessionHandleType, fileName []byte) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFDeleteFile(c.libHandle, C.SGD_HANDLE(sessionHandle), CMessage(fileName), C.SGD_UINT32(len(fileName)))
	err = ToError(err1)
	return err
}
