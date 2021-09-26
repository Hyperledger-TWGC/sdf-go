package sdf

import (
	"bytes"
	"fmt"
	"testing"
)

// 测试产生RSA密钥
func TestGenRSAKeyPair(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	fmt.Println("===SDFGenerateKeyPair_RSA===")
	var public RSArefPublicKey
	var private RSArefPrivateKey
	public, private, err := c.SDFGenerateKeyPair_RSA(s, 512)
	if err != nil {
		t.Fatal("generateKeyPair rsa error: ", err)
	}
	fmt.Println("Public Key Bits", public.Bits)
	fmt.Println("Public Key M", []byte(public.M))
	fmt.Println("Public Key E", []byte(public.E))
	fmt.Println("private Key Bits", private.Bits)
	fmt.Println("private Key M", []byte(private.M))
	fmt.Println("private Key E", []byte(private.E))
	fmt.Println("private Key D", []byte(private.D))
	fmt.Println("private Key Prime 0", []byte(private.Prime[0]))
	fmt.Println("private Key Prime 1", []byte(private.Prime[1]))
	fmt.Println("private Key Pexp 0", []byte(private.Pexp[0]))
	fmt.Println("private Key Pexp 1", []byte(private.Pexp[1]))
	fmt.Println("private Key Coef", []byte(private.Coef))
}

func TestExportRSAPuk(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	fmt.Println("===SDFExportSignPublicKey_RSA===")
	var signPublicKey RSArefPublicKey
	signPublicKey, err := c.SDFExportSignPublicKey_RSA(s, 1)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("SignPublicKey Key Bits", signPublicKey.Bits)
	fmt.Println("SignPublicKey Key M", []byte(signPublicKey.M))
	fmt.Println("SignPublicKey Key E", []byte(signPublicKey.E))

	fmt.Println("===SDFExportEncPublicKey_RSA===")
	var encPublicKey RSArefPublicKey
	encPublicKey, err = c.SDFExportEncPublicKey_RSA(s, 1)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("EncPublicKey Key Bits", encPublicKey.Bits)
	fmt.Println("EncPublicKey Key M", []byte(encPublicKey.M))
	fmt.Println("EncPublicKey Key E", []byte(encPublicKey.E))
}

func TestExtRSAOpt(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	fmt.Println("===SDFGenerateKeyPair_RSA===")
	publicKey, privateKey, err := c.SDFGenerateKeyPair_RSA(s, 1024)
	if err != nil {
		t.Fatal("generateKeyPair rsa error: ", err)
	}

	//产生随机加密数据
	fmt.Println("===SDFGenerateRandom===")
	randomData, err := c.SDFGenerateRandom(s, publicKey.Bits/8)
	if err != nil {
		t.Fatal("generate random encrypt data error: ", err)
	}
	fmt.Printf("random encrypt data: %x \n", randomData)

	fmt.Println("===SDFExternalPublicKeyOperation_RSA===")
	tmpData, err := c.SDFExternalPublicKeyOperation_RSA(s, publicKey, randomData, uint(len(randomData)))
	if err != nil {
		fmt.Println("ExternalPublicKeyOperation RSA error: ", err)
	}
	fmt.Printf("tmpData: %x \n", tmpData)

	fmt.Println("===SDFExternalPrivateKeyOperation_RSA===")
	outputData, err := c.SDFExternalPrivateKeyOperation_RSA(s, privateKey, tmpData, uint(len(tmpData)))
	if err != nil {
		fmt.Println("ExternalPublicKeyOperation RSA error: ", err)
	}
	fmt.Printf("outputData: %x \n", outputData)

}

func TestIntRSAOps(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	var keyIndex uint = 1
	fmt.Println("===SDFExportSignPublicKey_RSA===")
	signPublicKey, err := c.SDFExportSignPublicKey_RSA(s, keyIndex)
	if err != nil {
		fmt.Println("export sign publicKey RSA error: ", err)
	}
	fmt.Println(signPublicKey)

	fmt.Println("===SDFExportEncPublicKey_RSA===")
	encPublicKey, err := c.SDFExportEncPublicKey_RSA(s, keyIndex)
	if err != nil {
		fmt.Println("export encrypt publicKey RSA error: ", err)
	}
	randomData, err := c.SDFGenerateRandom(s, encPublicKey.Bits/8)
	if err != nil {
		fmt.Println("generate random encrypt data error: ", err)
	}
	fmt.Printf("random encrypt data: %x \n", randomData)

	fmt.Println("===SDFInternalPublicKeyOperation_RSA===")
	tmpData, err := c.SDFInternalPublicKeyOperation_RSA(s, keyIndex, randomData, (uint)(len(randomData)))
	if err != nil {
		fmt.Println("InternalPublicKey RSA error: ", err)
	}
	fmt.Println("tmpData ", tmpData)

	fmt.Println("===SDFInternalPrivateKeyOperation_RSA===")
	outputData, err := c.SDFInternalPrivateKeyOperation_RSA(s, keyIndex, tmpData, uint(len(tmpData)))
	if err != nil {
		fmt.Println("InternalPrivateKey RSA error: ", err)
	}
	fmt.Printf("outputData: %x \n", outputData)
}

func TestTransEnvelopRSA(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	var keyIndexSrc uint = 1
	var keyIndexDest uint = 1
	fmt.Println("===SDFGenerateKeyWithIPK_RSA===")
	keySrc, keySrcLength, keyDestHandle, err := c.SDFGenerateKeyWithIPK_RSA(s, keyIndexSrc, 128)
	if err != nil {
		fmt.Println("Generate RSA IPK Key error", err)
	}

	fmt.Println("===SDFExportEncPublicKey_RSA===")
	publicKey, err := c.SDFExportEncPublicKey_RSA(s, keyIndexDest)
	if err != nil {
		fmt.Println("Export Encrypt PublicKey error: ", err)
	}
	fmt.Println(publicKey.Bits)

	fmt.Println("===SDFExchangeDigitEnvelopeBaseOnRSA===")

	keyDest, outDestKeyLen, err := c.SDFExchangeDigitEnvelopeBaseOnRSA(s, keyIndexDest, publicKey, keySrc, keySrcLength)
	if err != nil {
		t.Fatal("Exchange Digit Envelope Base On RSA error: ", err)
	}
	fmt.Println(keyDest, outDestKeyLen)

	fmt.Println("===SDFImportKeyWithISK_RSA===")
	keySrcHandle, err := c.SDFImportKeyWithISK_RSA(s, keyIndexDest, keyDest, outDestKeyLen)
	if err != nil {
		t.Fatal("ImportKey With ISK RSA error: ", err)
	}

	fmt.Println("===SDFGenerateRandom===")
	var dataLength uint = 16
	randomData, err := c.SDFGenerateRandom(s, dataLength)
	if err != nil {
		t.Fatal("Generate random data error: ", err)
	}

	fmt.Println("===SDFEncrypt===")
	iv := []byte{0xd0, 0x4e, 0x51, 0xcd, 0xb1, 0x3c, 0x4a, 0xda, 0x34, 0x72, 0x44, 0xc3, 0x53, 0x29, 0x06, 0x24}
	encData, encDataLength, err := c.SDFEncrypt(s, keySrcHandle, SGD_SMS4_ECB, iv, randomData, 1024)
	if err != nil {
		t.Fatal("Encrypt Data error: ", err)
	}

	fmt.Println("===SDFDecrypt===")
	data, dataLength, err := c.SDFDecrypt(s, keyDestHandle, SGD_SMS4_ECB, iv, encData, encDataLength)
	if err != nil {
		t.Fatal("Decrypt Data error: ", err)
	}
	if bytes.Compare(randomData, data) == 0 {
		fmt.Println("Decrypt the data succeed!")
	}

	err = c.SDFDestroyKey(s, keySrcHandle)
	if err != nil {
		t.Fatal("DestroyKey error: ", err)
	}
	err = c.SDFDestroyKey(s, keyDestHandle)
	if err != nil {
		t.Fatal("DestroyKey error: ", err)
	}
}
