package sdf

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
