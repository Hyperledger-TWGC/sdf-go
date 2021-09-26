package sdf

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"testing"
)

func libPath() string {
	wd, _ := os.Getwd()
	if runtime.GOOS == "windows" {
		return wd + "\\sansec\\Win\\64\\swsds.dll"
	} else {
		return wd + "/sansec/Linux/64/libswsds.so"
	}
}
func Connect(t *testing.T) (c *Ctx, deviceHandle DeviceHandleType, sessionHandle SessionHandleType) {
	c = New(libPath())
	d, err := c.SDFOpenDevice()
	if err != nil {
		t.Fatal("open device error: ", err)
	}

	sessionHandle, err = c.SDFOpenSession(d)
	if err != nil {
		t.Fatal("open session error: ", err)
	}
	return
}
func Release(t *testing.T, c *Ctx, deviceHandle DeviceHandleType, sessionHandle SessionHandleType) {
	fmt.Println("defer func: Close Session...")
	err := c.SDFCloseSession(sessionHandle)
	if err != nil {
		t.Fatal("close session error: ", err)
	}

	fmt.Println("defer func: Close Device...")
	err = c.SDFCloseDevice(deviceHandle)
	if err != nil {
		t.Fatal("close device error: ", err)
	}
	c.Destroy()
}

// 基础函数测试
func TestBasicFunc(t *testing.T) {

	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	randomNum, err := c.SDFGenerateRandom(s, 16)
	if err != nil {
		t.Fatal("generate random error: ", err)
	}
	fmt.Println("random: ", randomNum)
	var info DeviceInfo
	info, err = c.SDFGetDeviceInfo(s)
	if err != nil {
		t.Fatal("get device information error: ", err)
	}
	fmt.Println("deviceInfo IssuerName: ", info.IssuerName)
	fmt.Println("deviceInfo DeviceName: ", info.DeviceName)
	fmt.Println("deviceInfo DeviceSerial: ", info.DeviceSerial)
	fmt.Println("deviceInfo DeviceVersion: ", info.DeviceVersion)
	fmt.Println("deviceInfo StandardVersion: ", info.StandardVersion)
	fmt.Println("deviceInfo AsymAlgAbility: ", info.AsymAlgAbility)
	fmt.Println("deviceInfo SymAlgAbility: ", info.SymAlgAbility)
	fmt.Println("deviceInfo HashAlgAbility: ", info.HashAlgAbility)
	fmt.Println("deviceInfo BufferSize: ", info.BufferSize)
}

func TestTransEnvelopECC(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)
	var keyIndexSrc uint = 1
	fmt.Println("===SDFGenerateKeyWithIPK_ECC===")
	pucKeySrc, keySrc, err := c.SDFGenerateKeyWithIPK_ECC(s, keyIndexSrc, 128)
	if err != nil {
		t.Fatal("Generate ECC IPK Key error", err)
	}

	fmt.Println("===SDFExportEncPublicKey_ECC===")
	pubKey, err := c.SDFExportEncPublicKey_ECC(s, keyIndexSrc)
	if err != nil {
		t.Fatal("Export EncPublicKey error: ", err)
	}

	fmt.Println("===SDFExchangeDigitEnvelopeBaseOnECC===")
	pucKeyDest, err := c.SDFExchangeDigitEnvelopeBaseOnECC(s, keyIndexSrc, SGD_SM2_3, pubKey, pucKeySrc)
	if err != nil {
		t.Fatal("Exchange Digit Envelope Base On ECC error: ", err)
	}

	fmt.Println("===SDFImportKeyWithISK_ECC===")
	keyDest, err := c.SDFImportKeyWithISK_ECC(s, 1, pucKeyDest)
	if err != nil {
		t.Fatal("Import Key With ISK ECC error: ", err)
	}

	fmt.Println("===SDFGenerateRandom===")
	var dataLength uint = 16
	randomData, err := c.SDFGenerateRandom(s, dataLength)
	if err != nil {
		t.Fatal("Generate Random Number error: ", err)
	}
	fmt.Printf("data %x dataLength %d \n", randomData, len(randomData))
	fmt.Println("===SDFEncrypt===")
	iv := []byte{0xd0, 0x4e, 0x51, 0xcd, 0xb1, 0x3c, 0x4a, 0xda, 0x34, 0x72, 0x44, 0xc3, 0x53, 0x29, 0x06, 0x24}
	encData, encDataLength, err := c.SDFEncrypt(s, keySrc, SGD_SM1_ECB, iv, randomData, 1024)
	if err != nil {
		t.Fatal("Encrypt Data error: ", err)
	}

	fmt.Println("===SDFDecrypt===")
	data, dataLength, err := c.SDFDecrypt(s, keyDest, SGD_SM1_ECB, iv, encData, encDataLength)
	if err != nil {
		t.Fatal("Decrypt Data error: ", err)
	}
	if bytes.Compare(randomData, data) == 0 {
		fmt.Println("Decrypt the data succeed!")
	}

	fmt.Println("===SDFDestroyKey===")
	err = c.SDFDestroyKey(s, keySrc)
	if err != nil {
		t.Fatal("DestroyKey error: ", err)
	}
	fmt.Println("===SDFDestroyKey===")
	err = c.SDFDestroyKey(s, keyDest)
	if err != nil {
		t.Fatal("DestroyKey error: ", err)
	}
}

func TestECCAgreement(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	var keyIndexSrc uint = 1
	fmt.Println("===SDFGenerateAgreementDataWithECC===")
	srcID := make([]byte, 16)
	for i := 0; i < 16; i++ {
		srcID[i] = 0x01
	}
	var srcIDLength uint = 16
	eccSrcPubKey, eccSrcTmpPubKey, agreementHandle, err := c.SDFGenerateAgreementDataWithECC(s, keyIndexSrc, 128, srcID, srcIDLength)
	if err != nil {
		fmt.Println("Generate Agreement Data With ECC  error: ", err)
		fmt.Println("===SDFReleasePrivateKeyAccessRight===")
		err = c.SDFReleasePrivateKeyAccessRight(s, keyIndexSrc)
		if err != nil {
			fmt.Println("Release privateKey access right error: ", err)
		}
	}

	var keyIndexDest uint = 1
	fmt.Println("===SDFGenerateAgreementDataAndKeyWithECC===")
	destID := make([]byte, 16)
	for i := 0; i < 16; i++ {
		destID[i] = 0x01
	}
	var destIDLength uint = 16
	eccDestPubKey, eccDestTmpPubKey, destKeyHandle, err := c.SDFGenerateAgreementDataAndKeyWithECC(s, keyIndexDest, 128, destID, destIDLength, srcID, srcIDLength, eccSrcPubKey, eccSrcTmpPubKey)
	if err != nil {
		fmt.Println("Generate Agreement Data And Key With ECC  error: ", err)
		fmt.Println("===SDFReleasePrivateKeyAccessRight===")
		err = c.SDFReleasePrivateKeyAccessRight(s, keyIndexSrc)
		if err != nil {
			fmt.Println("Release privateKey access right error: ", err)
		}
		fmt.Println("===SDFReleasePrivateKeyAccessRight===")
		err = c.SDFReleasePrivateKeyAccessRight(s, keyIndexDest)
		if err != nil {
			fmt.Println("Release privateKey access right error: ", err)
		}
	}

	fmt.Println("===SDFGenerateKeyWithECC===")
	srcKeyHandle, err := c.SDFGenerateKeyWithECC(s, destID, destIDLength, eccDestPubKey, eccDestTmpPubKey, agreementHandle)
	if err != nil {
		fmt.Println("Generate Agreement Data With ECC  error: ", err)
		fmt.Println("===SDFReleasePrivateKeyAccessRight===")
		err = c.SDFReleasePrivateKeyAccessRight(s, keyIndexSrc)
		if err != nil {
			fmt.Println("Release privateKey access right error: ", err)
		}
		fmt.Println("===SDFReleasePrivateKeyAccessRight===")
		err = c.SDFReleasePrivateKeyAccessRight(s, keyIndexDest)
		if err != nil {
			fmt.Println("Release privateKey access right error: ", err)
		}
	}

	fmt.Println("===SDFGenerateRandom===")
	var dataLength uint = 32
	randomData, err := c.SDFGenerateRandom(s, dataLength)
	if err != nil {
		fmt.Println("Generate Random num  error: ", err)
	}
	fmt.Printf("randomData %x randomDataLength %x \n", randomData, 128)
	fmt.Println("===SDFEncrypt===")
	iv := []byte{0xd0, 0x4e, 0x51, 0xcd, 0xb1, 0x3c, 0x4a, 0xda, 0x34, 0x72, 0x44, 0xc3, 0x53, 0x29, 0x06, 0x24}
	encData, encDataLength, err := c.SDFEncrypt(s, srcKeyHandle, SGD_SMS4_ECB, iv, randomData, 128)
	if err != nil {
		fmt.Println("Encrypt Data error: ", err)
	}

	fmt.Println("===SDFDecrypt===")
	data, dataLength, err := c.SDFDecrypt(s, destKeyHandle, SGD_SMS4_ECB, iv, encData, encDataLength)
	if err != nil {
		fmt.Println("Decrypt Data error: ", err)
	}
	if bytes.Compare(randomData, data) == 0 {
		fmt.Println("Decrypt the data succeed!")
	}

	fmt.Println("===SDFDestroyKey===")
	err = c.SDFDestroyKey(s, srcKeyHandle)
	if err != nil {
		fmt.Println("DestroyKey error: ", err)
	}
	fmt.Println("===SDFDestroyKey===")
	err = c.SDFDestroyKey(s, destKeyHandle)
	if err != nil {
		fmt.Println("DestroyKey error: ", err)
	}
}

func TestExportECCPuk(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	fmt.Println("===SDFExportSignPublicKey_ECC===")
	var signPublicKey ECCrefPublicKey
	signPublicKey, err := c.SDFExportSignPublicKey_ECC(s, 1)
	if err != nil {
		fmt.Println("export sign publickey pair error: ", err)
	}
	fmt.Println("SignPublic Key Bits", signPublicKey.Bits)
	fmt.Println("SignPublic Key X", []byte(signPublicKey.X))
	fmt.Println("SignPublic Key Y", []byte(signPublicKey.Y))

	fmt.Println("===SDFExportEncPublicKey_ECC===")
	var encPublicKey ECCrefPublicKey
	encPublicKey, err = c.SDFExportEncPublicKey_ECC(s, 1)
	if err != nil {
		fmt.Println("export encrypt publickey pair error: ", err)
	}
	fmt.Println("EncPublic Key Bits", encPublicKey.Bits)
	fmt.Println("EncPublic Key X", []byte(encPublicKey.X))
	fmt.Println("EncPublic Key Y", []byte(encPublicKey.Y))

}

func TestHashFunc(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	data := []byte{0x61, 0x62, 0x63}
	_, err := c.SDFHashInit(s, SGD_SM3, nil, 0)
	if err != nil {
		fmt.Println("Hash init error: ", err)
	}
	err = c.SDFHashUpdate(s, data, 3)
	if err != nil {
		fmt.Println("Hash Update error: ", err)
	}
	hash, hashLength, err := c.SDFHashFinal(s)
	if err != nil {
		fmt.Println("write file error: ", err)
	}
	fmt.Printf("hash:%x hashLength:%d \n", hash, hashLength)

}

func TestReleasePrivateKeyAccessRight(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	key, keyHandle, err := c.SDFGenerateKeyWithIPK_ECC(s, 1, 256)
	if err != nil {
		fmt.Println("SDFGenerateKeyWithIPK_ECC", err)
	}
	fmt.Println("===SDFGenerateKeyWithIPK_ECC===")
	fmt.Println("keyHandle", keyHandle)
	fmt.Println("Key X ", []byte(key.X))
	fmt.Println("Key Y ", []byte(key.Y))
	fmt.Println("Key M ", []byte(key.M))
	fmt.Println("Key C ", []byte(key.C))
	fmt.Println("Key L ", key.L)

	fmt.Println("===SDFReleasePrivateKeyAccessRight===")
	err = c.SDFReleasePrivateKeyAccessRight(s, 1)
	if err != nil {
		fmt.Println("Release privateKey access right error: ", err)
	}

}

func TestIntECCSign(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	var publicKey ECCrefPublicKey
	var privateKey ECCrefPrivateKey
	publicKey, privateKey, err := c.SDFGenerateKeyPair_ECC(s, SGD_SM2_3, 256)
	fmt.Println("===SDFGenerateKeyPair_ECC===")
	fmt.Println("Public Key Bits", publicKey.Bits)
	fmt.Println("Public Key X", []byte(publicKey.X))
	fmt.Println("Public Key Y", []byte(publicKey.Y))
	fmt.Println("private Key Bits", privateKey.Bits)
	fmt.Println("private Key K", []byte(privateKey.K))

	inHashData := []byte{0xbc, 0xa3, 0xde, 0xa1, 0x2f, 0x89, 0xd7, 0x78, 0xe5, 0xb7, 0x0b, 0x86, 0x7d, 0x1e, 0x36, 0x0e, 0x93, 0x7d, 0x47, 0xcb, 0xbb, 0xac, 0x39, 0x06, 0x35, 0x81, 0xa4, 0xe1, 0x85, 0x76, 0x57, 0x31}
	fmt.Println("===SDFInternalSign_ECC===")
	signature, err := c.SDFInternalSign_ECC(s, 1, inHashData, 32)
	if err != nil {
		fmt.Println("Internal sign error: ", err)
	}

	fmt.Println("===SDFInternalVerify_ECC===")
	err = c.SDFInternalVerify_ECC(s, 1, inHashData, 32, signature)
	if err != nil {
		fmt.Println("Internal verify error: ", err)
	} else {
		fmt.Println("Internal verify succeed! ")
	}

}

func TestIntECCEnc(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	var publicKey ECCrefPublicKey
	var privateKey ECCrefPrivateKey
	publicKey, privateKey, err := c.SDFGenerateKeyPair_ECC(s, SGD_SM2_3, 256)
	fmt.Println("===SDFGenerateKeyPair_ECC===")
	fmt.Println("Public Key Bits", publicKey.Bits)
	fmt.Println("Public Key X", []byte(publicKey.X))
	fmt.Println("Public Key Y", []byte(publicKey.Y))
	fmt.Println("private Key Bits", privateKey.Bits)
	fmt.Println("private Key K", []byte(privateKey.K))

	inHashData := []byte{0xbc, 0xa3, 0xde, 0xa1, 0x2f, 0x89, 0xd7, 0x78, 0xe5, 0xb7, 0x0b, 0x86, 0x7d, 0x1e, 0x36, 0x0e, 0x93, 0x7d, 0x47, 0xcb, 0xbb, 0xac, 0x39, 0x06, 0x35, 0x81, 0xa4, 0xe1, 0x85, 0x76, 0x57, 0x31}
	fmt.Println("===SDFInternalEncrypt_ECC===")
	fmt.Printf("plain data %x ,dataLength %d  \n", inHashData, len(inHashData))
	encData, err := c.SDFInternalEncrypt_ECC(s, 1, SGD_SM2_3, inHashData, 32)
	if err != nil {
		fmt.Println("Internal encrypt error: ", err)
	}

	fmt.Println("===SDFInternalDecrypt_ECC===")
	data, dataLength, err := c.SDFInternalDecrypt_ECC(s, 1, SGD_SM2_3, encData)
	if err != nil {
		fmt.Println("Internal decrypt error: ", err)
	}
	fmt.Printf("decrypted data %x  ,dataLength %d \n ", data, dataLength)

}

func TestExtECCSign(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	var publicKey ECCrefPublicKey
	var privateKey ECCrefPrivateKey
	publicKey, privateKey, err := c.SDFGenerateKeyPair_ECC(s, SGD_SM2_1, 256)
	fmt.Println("===SDFGenerateKeyPair_ECC===")
	fmt.Println("Public Key Bits", publicKey.Bits)
	fmt.Println("Public Key X", []byte(publicKey.X))
	fmt.Println("Public Key Y", []byte(publicKey.Y))
	fmt.Println("private Key Bits", privateKey.Bits)
	fmt.Println("private Key K", []byte(privateKey.K))

	fmt.Println("===SDFExternalSign_ECC===")
	inputData := []byte{0xbc, 0xa3, 0xde, 0xa1, 0x2f, 0x89, 0xd7, 0x78, 0xe5, 0xb7, 0x0b, 0x86, 0x7d, 0x1e, 0x36, 0x0e, 0x93, 0x7d, 0x47, 0xcb, 0xbb, 0xac, 0x39, 0x06, 0x35, 0x81, 0xa4, 0xe1, 0x85, 0x76, 0x57, 0x31}
	fmt.Printf("plain data %x \n", inputData)
	signData, err := c.SDFExternalSign_ECC(s, SGD_SM2_1, privateKey, inputData, 32)
	if err != nil {
		fmt.Println("External Sign error: ", err)
	}
	fmt.Printf("signData R %x \n", []byte(signData.R))
	fmt.Printf("signData S %x \n", []byte(signData.S))

	fmt.Println("===SDFExternalVerify_ECC===")
	err = c.SDFExternalVerify_ECC(s, SGD_SM2_1, publicKey, inputData, 32, signData)
	if err != nil {
		fmt.Println("External Verify error: ", err)
	} else {
		fmt.Println("External verify succeed! ")
	}

}

func TestExtECCEnc(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	var publicKey ECCrefPublicKey
	var privateKey ECCrefPrivateKey
	publicKey, privateKey, err := c.SDFGenerateKeyPair_ECC(s, SGD_SM2_2, 256)
	fmt.Println("===SDFGenerateKeyPair_ECC===")
	fmt.Println("Public Key Bits", publicKey.Bits)
	fmt.Println("Public Key X", []byte(publicKey.X))
	fmt.Println("Public Key Y", []byte(publicKey.Y))
	fmt.Println("private Key Bits", privateKey.Bits)
	fmt.Println("private Key K", []byte(privateKey.K))

	inputData := []byte{0xbc, 0xa3, 0xde, 0xa1, 0x2f, 0x89, 0xd7, 0x78, 0xe5, 0xb7, 0x0b, 0x86, 0x7d, 0x1e, 0x36, 0x0e, 0x93, 0x7d, 0x47, 0xcb, 0xbb, 0xac, 0x39, 0x06, 0x35, 0x81, 0xa4, 0xe1, 0x85, 0x76, 0x57, 0x31}
	fmt.Println("===SDFExternalEncrypt_ECC===")
	encData, err := c.SDFExternalEncrypt_ECC(s, SGD_SM2_2, publicKey, inputData, 32)
	if err != nil {
		fmt.Println("External Encrypt  error: ", err)
	}

	fmt.Println("===SDFExternalDecrypt_ECC===")
	decData, decDataLength, err := c.SDFExternalDecrypt_ECC(s, SGD_SM2_2, privateKey, encData)
	if err != nil {
		fmt.Println("External Decrypt  error: ", err)
	}
	fmt.Printf("decrypt data %x decrypt data length %d \n", decData, decDataLength)
}

func TestGenerateECCFunc(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	fmt.Println("===SDFGenerateKeyWithIPK_ECC===")
	key, keyHandle, err := c.SDFGenerateKeyWithIPK_ECC(s, 1, 256)
	if err != nil {
		fmt.Println("SDFGenerateKeyWithIPK_ECC", err)
	}
	fmt.Println("keyHandle", keyHandle)
	fmt.Println("Key X ", []byte(key.X))
	fmt.Println("Key Y ", []byte(key.Y))
	fmt.Println("Key M ", []byte(key.M))
	fmt.Println("Key C ", []byte(key.C))
	fmt.Println("Key L ", key.L)

	fmt.Println("===SDFExportEncPublicKey_ECC===")
	publicKey, err := c.SDFExportEncPublicKey_ECC(s, 1)
	if err != nil {
		fmt.Println("Export EncPublicKey error: ", err)
	} else {
		fmt.Println("Public Key Bits", publicKey.Bits)
		fmt.Println("Public Key X", []byte(publicKey.X))
		fmt.Println("Public Key Y", []byte(publicKey.Y))

		key1, keyHandle1, err := c.SDFGenerateKeyWithEPK_ECC(s, 256, SGD_SM2_2, publicKey)
		if err != nil {
			fmt.Println("SDFGenerateKeyWithEPK RSA error: ", err)
		}
		fmt.Println("===SDFGenerateKeyWithEPK_ECC===")
		fmt.Println("Public Key X", []byte(key1.X))
		fmt.Println("Public Key Y", []byte(key1.Y))
		fmt.Println("Public Key M", []byte(key1.M))
		fmt.Println("keyHandle1 ", keyHandle1)
	}

}

func TestEncryptFunc(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	var length uint = 32
	randomNum, err := c.SDFGenerateRandom(s, length)
	if err != nil {
		fmt.Println("generate random error: ", err)
	}
	fmt.Println("random number for key: ", randomNum)

	keyHandle, err := c.SDFImportKey(s, randomNum, 32)
	if err != nil {
		fmt.Println("Import key error: ", err)
	}

	iv := []byte{0xd0, 0x4e, 0x51, 0xcd, 0xb1, 0x3c, 0x4a, 0xda, 0x34, 0x72, 0x44, 0xc3, 0x53, 0x29, 0x06, 0x24}
	inData := []byte{0xbc, 0xa3, 0xde, 0xa1, 0x2f, 0x89, 0xd7, 0x78, 0xe5, 0xb7, 0x0b, 0x86, 0x7d, 0x1e, 0x36, 0x0e, 0x93, 0x7d, 0x47, 0xcb, 0xbb, 0xac, 0x39, 0x06, 0x35, 0x81, 0xa4, 0xe1, 0x85, 0x76, 0x57, 0x31}
	fmt.Printf("inData:%x inDataLength:%d \n", inData, len(inData))

	encData, encDataLength, err := c.SDFEncrypt(s, keyHandle, SGD_SMS4_ECB, iv, inData, uint(len(inData)))
	if err != nil {
		fmt.Println("Encrypt data error: ", err)
	}
	fmt.Printf("encData:%x encDataLength:%d \n", encData, encDataLength)

	data, dataLength, err := c.SDFDecrypt(s, keyHandle, SGD_SMS4_ECB, iv, encData, encDataLength)
	if err != nil {
		fmt.Println("Decrypt data error: ", err)
	}
	fmt.Printf("data:%x dataLength:%d \n", data, dataLength)

	err = c.SDFDestroyKey(s, keyHandle)
	if err != nil {
		fmt.Println("Destroy key error: ", err)
	}

}

func TestSDFMAC(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)
	fmt.Println("===SDFGenerateRandom===")
	var length uint = 16
	randomNum, err := c.SDFGenerateRandom(s, length)
	if err != nil {
		fmt.Println("generate random error: ", err)
	}
	fmt.Println("random number for key: ", randomNum)

	fmt.Println("===SDFImportKey===")
	keyHandle, err := c.SDFImportKey(s, randomNum, 16)
	if err != nil {
		fmt.Println("Import key error: ", err)
	}

	fmt.Println("===SDFCalculateMAC===")
	iv := []byte{0xd0, 0x4e, 0x51, 0xcd, 0xb1, 0x3c, 0x4a, 0xda, 0x34, 0x72, 0x44, 0xc3, 0x53, 0x29, 0x06, 0x24}
	mac, macLength, err := c.SDFCalculateMAC(s, keyHandle, SGD_SMS4_MAC, iv, randomNum, uint(len(randomNum)))
	if err != nil {
		fmt.Println("Decrypt data error: ", err)
	}
	fmt.Printf("mac:%x macLength:%d \n", mac, macLength)

	fmt.Println("===SDFDestroyKey===")
	err = c.SDFDestroyKey(s, keyHandle)
	if err != nil {
		fmt.Println("Destroy key error: ", err)
	}
}
