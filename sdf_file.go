package sdf

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
