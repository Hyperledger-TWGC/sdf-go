package sdf

import (
	"bytes"
	"fmt"
	"github.com/Hyperledger-TWGC/sdf-go/core"
	"github.com/Hyperledger-TWGC/sdf-go/util"
	"os"
	"runtime"
	"testing"
)

const path string=""

func init(){
	if len(path)!=0{
			util.InitLogFile(path,"connect.log")
	}else {
		wd,err := os.Getwd()
		if err == nil{
			util.InitLogFile(wd,"connect.log")
		}
	}
}

func libPath() string{
	wd,_ := os.Getwd()
	if runtime.GOOS=="windows"{
		return wd+"\\sansec\\Win\\64\\swsds.dll"
	}else {
		return wd+"/sansec/Linux/64/libswsds.so"
	}
}




// 基础函数测试
func TestBasicFunc(t *testing.T) {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	randomNum,err:=c.SDFGenerateRandom(s,16)
	if err != nil{
		fmt.Println("generate random error: ",err)
	}
	fmt.Println("random: ",randomNum)
	var info core.DeviceInfo
	info,err = c.SDFGetDeviceInfo(s)
	if err != nil{
		fmt.Println("get device information error: ",err)
	}
	fmt.Println("deviceInfo IssuerName: ",info.IssuerName)
	fmt.Println("deviceInfo DeviceName: ",info.DeviceName)
	fmt.Println("deviceInfo DeviceSerial: ",info.DeviceSerial)
	fmt.Println("deviceInfo DeviceVersion: ",info.DeviceVersion)
	fmt.Println("deviceInfo StandardVersion: ",info.StandardVersion)
 	fmt.Println("deviceInfo AsymAlgAbility: ",info.AsymAlgAbility)
	fmt.Println("deviceInfo SymAlgAbility: ",info.SymAlgAbility)
	fmt.Println("deviceInfo HashAlgAbility: ",info.HashAlgAbility)
	fmt.Println("deviceInfo BufferSize: ",info.BufferSize)
}

// RSA测试
// 测试产生RSA密钥
func TestGenRSAKeyPair(t *testing.T) {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()
	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	fmt.Println("===SDFGenerateKeyPair_RSA===")
	var public core.RSArefPublicKey
	var private core.RSArefPrivateKey
	public,private,err = c.SDFGenerateKeyPair_RSA(s,512)
	if err != nil{
		fmt.Println("generateKeyPair rsa error: ",err)
	}
	fmt.Println("Public Key Bits",public.Bits)
	fmt.Println("Public Key M",[]byte(public.M))
	fmt.Println("Public Key E",[]byte(public.E))
	fmt.Println("private Key Bits",private.Bits)
	fmt.Println("private Key M",[]byte(private.M))
	fmt.Println("private Key E",[]byte(private.E))
	fmt.Println("private Key D",[]byte(private.D))
	fmt.Println("private Key Prime 0",[]byte(private.Prime[0]))
	fmt.Println("private Key Prime 1",[]byte(private.Prime[1]))
	fmt.Println("private Key Pexp 0",[]byte(private.Pexp[0]))
	fmt.Println("private Key Pexp 1",[]byte(private.Pexp[1]))
	fmt.Println("private Key Coef",[]byte(private.Coef))
}

func TestExportRSAPuk(t *testing.T)  {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()
	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	fmt.Println("===SDFExportSignPublicKey_RSA===")
	var signPublicKey core.RSArefPublicKey
	signPublicKey,err = c.SDFExportSignPublicKey_RSA(s,1)
	fmt.Println("SignPublicKey Key Bits",signPublicKey.Bits)
	fmt.Println("SignPublicKey Key M",[]byte(signPublicKey.M))
	fmt.Println("SignPublicKey Key E",[]byte(signPublicKey.E))

	fmt.Println("===SDFExportEncPublicKey_RSA===")
	var encPublicKey core.RSArefPublicKey
	encPublicKey,err = c.SDFExportEncPublicKey_RSA(s,1)
	fmt.Println("EncPublicKey Key Bits",encPublicKey.Bits)
	fmt.Println("EncPublicKey Key M",[]byte(encPublicKey.M))
	fmt.Println("EncPublicKey Key E",[]byte(encPublicKey.E))
}

func TestExtRSAOpt(t *testing.T)  {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()
	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	fmt.Println("===SDFGenerateKeyPair_RSA===")
	publicKey,privateKey,err := c.SDFGenerateKeyPair_RSA(s,1024)
	if err != nil{
		fmt.Println("generateKeyPair rsa error: ",err)
	}

	//产生随机加密数据
	fmt.Println("===SDFGenerateRandom===")
	randomData,err:=c.SDFGenerateRandom(s,publicKey.Bits/8)
	if err != nil{
		fmt.Println("generate random encrypt data error: ",err)
	}
	fmt.Printf("random encrypt data: %x \n",randomData)

	fmt.Println("===SDFExternalPublicKeyOperation_RSA===")
	tmpData,err:=c.SDFExternalPublicKeyOperation_RSA(s,publicKey,randomData,uint(len(randomData)))
	if err != nil{
		fmt.Println("ExternalPublicKeyOperation RSA error: ",err)
	}
	fmt.Printf("tmpData: %x \n",tmpData)


	fmt.Println("===SDFExternalPrivateKeyOperation_RSA===")
	outputData,err:=c.SDFExternalPrivateKeyOperation_RSA(s,privateKey,tmpData,uint(len(tmpData)))
	if err != nil{
		fmt.Println("ExternalPublicKeyOperation RSA error: ",err)
	}
	fmt.Printf("outputData: %x \n",outputData)


}


func TestIntRSAOps(t *testing.T)  {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err:=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err:=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	var keyIndex uint= 1
	fmt.Println("===SDFExportSignPublicKey_RSA===")
	signPublicKey,err := c.SDFExportSignPublicKey_RSA(s,keyIndex)
	if err != nil{
		fmt.Println("export sign publicKey RSA error: ",err)
	}
	fmt.Println(signPublicKey)

	fmt.Println("===SDFExportEncPublicKey_RSA===")
	encPublicKey,err := c.SDFExportEncPublicKey_RSA(s,keyIndex)
	if err != nil{
		fmt.Println("export encrypt publicKey RSA error: ",err)
	}
 	fmt.Println(encPublicKey)
	//产生随机加密数据
	randomData,err:=c.SDFGenerateRandom(s,encPublicKey.Bits/8)
	if err != nil{
		fmt.Println("generate random encrypt data error: ",err)
	}
	fmt.Printf("random encrypt data: %x \n",randomData)


	fmt.Println("===SDFInternalPublicKeyOperation_RSA===")
	tmpData,err := c.SDFInternalPublicKeyOperation_RSA(s,keyIndex,randomData,(uint)(len(randomData)))
	if err != nil{
		fmt.Println("InternalPublicKey RSA error: ",err)
	}
	fmt.Println("tmpData ",tmpData)

	fmt.Println("===SDFInternalPrivateKeyOperation_RSA===")
	outputData,err:=c.SDFInternalPrivateKeyOperation_RSA(s,keyIndex,tmpData,uint(len(tmpData)))
	if err != nil{
		fmt.Println("InternalPrivateKey RSA error: ",err)
	}
	fmt.Printf("outputData: %x \n",outputData)
}


func TestTransEnvelopRSA(t *testing.T) {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()
	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	var keyIndexSrc  uint =1
    var keyIndexDest uint = 1
	fmt.Println("===SDFGenerateKeyWithIPK_RSA===")
	keySrc,keySrcLength,_,err := c.SDFGenerateKeyWithIPK_RSA(s,keyIndexSrc,128)
	if err != nil {
		fmt.Println("Generate RSA IPK Key error",err)
	}
	//fmt.Printf("keySrc %x keySrcLength %d keySrcHandle %x \n",keySrc,keySrcLength,keySrcHandle)

	fmt.Println("===SDFExportEncPublicKey_RSA===")
	publicKey,err:=c.SDFExportEncPublicKey_RSA(s,keyIndexDest)
	if err != nil{
		fmt.Println("Export Encrypt PublicKey error: ",err)
	}
	fmt.Println(publicKey.Bits)

	fmt.Println("===SDFExchangeDigitEnvelopeBaseOnRSA===")
	_,_,err=c.SDFExchangeDigitEnvelopeBaseOnRSA(s,keyIndexDest,publicKey,keySrc,keySrcLength)
	//keyDest,outDestKeyLen,err:=c.SDFExchangeDigitEnvelopeBaseOnRSA(s,keyIndexDest,publicKey,keySrc,keySrcLength)
	if err != nil{
		fmt.Println("Exchange Digit Envelope Base On RSA error: ",err)
	}
	//fmt.Println(keyDest,outDestKeyLen)

	//fmt.Println("===SDFImportKeyWithISK_RSA===")
	//_,err=c.SDFImportKeyWithISK_RSA(s,keyIndexDest,keyDest,outDestKeyLen)
	////keyDestHandle,err:=c.SDFImportKeyWithISK_RSA(s,keyIndexDest,keyDest,outDestKeyLen)
	//if err != nil{
	//	fmt.Println("ImportKey With ISK RSA error: ",err)
	//}

	//fmt.Println("===SDFGenerateRandom===")
	//randomData,err:=c.SDFGenerateRandom(s,1024)
	//if err != nil{
	//	fmt.Println("Generate random data error: ",err)
	//}
	//
	//fmt.Println("===SDFEncrypt===")
	//iv :=[]byte{ 0xd0,0x4e ,0x51 ,0xcd ,0xb1 ,0x3c ,0x4a ,0xda ,0x34 ,0x72 ,0x44 ,0xc3 ,0x53 ,0x29 ,0x06 ,0x24 }
	//encData,encDataLength,err :=c.SDFEncrypt(s,keySrcHandle,core.SGD_SM1_ECB,iv,randomData,1024)
	//if err!= nil{
	//	fmt.Println("Encrypt Data error: ",err)
	//}
	//
	//fmt.Println("===SDFDecrypt===")
	//data,dataLength,err := c.SDFDecrypt(s,keyDestHandle,core.SGD_SM1_ECB,iv,encData,encDataLength)
	//if err!= nil{
	//	fmt.Println("Decrypt Data error: ",err)
	//}
	//fmt.Printf("data %x dataLength %x \n",data,dataLength)
	//
	//err = c.SDFDestroyKey(s,keySrcHandle)
	//if err!= nil{
	//	fmt.Println("DestroyKey error: ",err)
	//}
	//err = c.SDFDestroyKey(s,keyDestHandle)
	//if err!= nil{
	//	fmt.Println("DestroyKey error: ",err)
	//}
}


func TestTransEnvelopECC(t *testing.T) {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()
	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()
	var keyIndexSrc uint=1
	fmt.Println("===SDFGenerateKeyWithIPK_ECC===")
	pucKeySrc,keySrc,err := c.SDFGenerateKeyWithIPK_ECC(s,keyIndexSrc,128)
	if err != nil {
		fmt.Println("Generate ECC IPK Key error",err)
	}

	fmt.Println("===SDFExportEncPublicKey_ECC===")
	pubKey,err:=c.SDFExportEncPublicKey_ECC(s,keyIndexSrc)
	if err != nil{
		fmt.Println("Export EncPublicKey error: ",err)
	}

	fmt.Println("===SDFExchangeDigitEnvelopeBaseOnECC===")
	pucKeyDest,err:=c.SDFExchangeDigitEnvelopeBaseOnECC(s,keyIndexSrc,core.SGD_SM2_3,pubKey,pucKeySrc)
	if err != nil{
		fmt.Println("Exchange Digit Envelope Base On ECC error: ",err)
	}


	fmt.Println("===SDFImportKeyWithISK_ECC===")
	keyDest,err:=c.SDFImportKeyWithISK_ECC(s,1,pucKeyDest)
	if err != nil{
		fmt.Println("Import Key With ISK ECC error: ",err)
	}

	fmt.Println("===SDFGenerateRandom===")
	randomData,err:=c.SDFGenerateRandom(s,1024)
	if err != nil{
		fmt.Println("Generate Random Number error: ",err)
	}
	fmt.Printf("data %x dataLength %d \n",randomData,len(randomData))
	fmt.Println("===SDFEncrypt===")
	iv :=[]byte{ 0xd0,0x4e ,0x51 ,0xcd ,0xb1 ,0x3c ,0x4a ,0xda ,0x34 ,0x72 ,0x44 ,0xc3 ,0x53 ,0x29 ,0x06 ,0x24 }
	encData,encDataLength,err :=c.SDFEncrypt(s,keySrc,core.SGD_SM1_ECB,iv,randomData,1024)
	if err!= nil{
		fmt.Println("Encrypt Data error: ",err)
	}

	fmt.Println("===SDFDecrypt===")
	data,dataLength,err := c.SDFDecrypt(s,keyDest,core.SGD_SM1_ECB,iv,encData,encDataLength)
	if err!= nil{
		fmt.Println("Decrypt Data error: ",err)
	}
	fmt.Printf("data %x dataLength %d \n",data,dataLength)

	fmt.Println("===SDFDestroyKey===")
	err = c.SDFDestroyKey(s,keySrc)
	if err!= nil{
		fmt.Println("DestroyKey error: ",err)
	}
	fmt.Println("===SDFDestroyKey===")
	err = c.SDFDestroyKey(s,keyDest)
	if err!= nil{
		fmt.Println("DestroyKey error: ",err)
	}
}

func TestECCAgreement(t *testing.T) {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()
	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	var keyIndexSrc uint=1
	fmt.Println("===SDFGenerateAgreementDataWithECC===")
	srcID:=make([]byte,16)
	for i:=0;i<16;i++{
		srcID[i]=0x01
	}
	var srcIDLength uint=16
	eccSrcPubKey,eccSrcTmpPubKey,agreementHandle,err := c.SDFGenerateAgreementDataWithECC(s,keyIndexSrc,128,srcID,srcIDLength)
	if err!= nil{
		fmt.Println("Generate Agreement Data With ECC  error: ",err)
		fmt.Println("===SDFReleasePrivateKeyAccessRight===")
		err = c.SDFReleasePrivateKeyAccessRight(s,keyIndexSrc)
		if err != nil{
			fmt.Println("Release privateKey access right error: ",err)
		}
	}

	var keyIndexDest uint = 1
	fmt.Println("===SDFGenerateAgreementDataAndKeyWithECC===")
	destID:=make([]byte,16)
	for i:=0;i<16;i++{
		destID[i]=0x01
	}
	var destIDLength uint=16
	eccDestPubKey,eccDestTmpPubKey,destKeyHandle,err:=c.SDFGenerateAgreementDataAndKeyWithECC(s,keyIndexDest,128,destID,destIDLength,srcID,srcIDLength,eccSrcPubKey,eccSrcTmpPubKey)
	if err!= nil{
		fmt.Println("Generate Agreement Data And Key With ECC  error: ",err)
		fmt.Println("===SDFReleasePrivateKeyAccessRight===")
		err = c.SDFReleasePrivateKeyAccessRight(s,keyIndexSrc)
		if err != nil{
			fmt.Println("Release privateKey access right error: ",err)
		}
		fmt.Println("===SDFReleasePrivateKeyAccessRight===")
		err = c.SDFReleasePrivateKeyAccessRight(s,keyIndexDest)
		if err != nil{
			fmt.Println("Release privateKey access right error: ",err)
		}
	}

	fmt.Println("===SDFGenerateKeyWithECC===")
	srcKeyHandle,err :=c.SDFGenerateKeyWithECC(s,destID,destIDLength,eccDestPubKey,eccDestTmpPubKey,agreementHandle)
	if err!= nil{
		fmt.Println("Generate Agreement Data With ECC  error: ",err)
		fmt.Println("===SDFReleasePrivateKeyAccessRight===")
		err = c.SDFReleasePrivateKeyAccessRight(s,keyIndexSrc)
		if err != nil{
			fmt.Println("Release privateKey access right error: ",err)
		}
		fmt.Println("===SDFReleasePrivateKeyAccessRight===")
		err = c.SDFReleasePrivateKeyAccessRight(s,keyIndexDest)
		if err != nil{
			fmt.Println("Release privateKey access right error: ",err)
		}
	}

	fmt.Println("===SDFGenerateRandom===")
	randomData,err := c.SDFGenerateRandom(s,128)
	if err!= nil{
		fmt.Println("Generate Random num  error: ",err)
	}
	fmt.Printf("randomData %x randomDataLength %x \n",randomData,128)
	fmt.Println("===SDFEncrypt===")
	iv :=[]byte{ 0xd0,0x4e ,0x51 ,0xcd ,0xb1 ,0x3c ,0x4a ,0xda ,0x34 ,0x72 ,0x44 ,0xc3 ,0x53 ,0x29 ,0x06 ,0x24 }
	encData,encDataLength,err :=c.SDFEncrypt(s,srcKeyHandle,core.SGD_SM1_ECB,iv,randomData,128)
	if err!= nil{
		fmt.Println("Encrypt Data error: ",err)
	}

	fmt.Println("===SDFDecrypt===")
	data,dataLength,err := c.SDFDecrypt(s,destKeyHandle,core.SGD_SM1_ECB,iv,encData,encDataLength)
	if err!= nil{
		fmt.Println("Decrypt Data error: ",err)
	}
	fmt.Printf("data %x dataLength %x \n",data,dataLength)

	if(bytes.Compare(randomData,data)==0){
		fmt.Println("Decrypt the data succeed!")
	}
	fmt.Println("===SDFDestroyKey===")
	err = c.SDFDestroyKey(s,srcKeyHandle)
	if err!= nil{
		fmt.Println("DestroyKey error: ",err)
	}
	fmt.Println("===SDFDestroyKey===")
	err = c.SDFDestroyKey(s,destKeyHandle)
	if err!= nil{
		fmt.Println("DestroyKey error: ",err)
	}
}


func TestExportECCPuk(t *testing.T) {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err:=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()
	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err:=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	fmt.Println("===SDFExportSignPublicKey_ECC===")
	var signPublicKey core.ECCrefPublicKey
	signPublicKey,err = c.SDFExportSignPublicKey_ECC(s,1)
	if err != nil{
		fmt.Println("export sign publickey pair error: ",err)
	}
	fmt.Println("SignPublic Key Bits",signPublicKey.Bits)
	fmt.Println("SignPublic Key X",[]byte(signPublicKey.X))
	fmt.Println("SignPublic Key Y",[]byte(signPublicKey.Y))

	fmt.Println("===SDFExportEncPublicKey_ECC===")
	var encPublicKey core.ECCrefPublicKey
	encPublicKey,err = c.SDFExportEncPublicKey_ECC(s,1)
	if err != nil{
		fmt.Println("export encrypt publickey pair error: ",err)
	}
	fmt.Println("EncPublic Key Bits",encPublicKey.Bits)
	fmt.Println("EncPublic Key X",[]byte(encPublicKey.X))
	fmt.Println("EncPublic Key Y",[]byte(encPublicKey.Y))


}

func TestHashFunc(t *testing.T) {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err:=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err:=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	data:=[]byte{0x61,0x62,0x63}
	_,err=c.SDFHashInit(s,core.SGD_SM3,nil,0)
	if err != nil{
		fmt.Println("Hash init error: ",err)
	}
	err = c.SDFHashUpdate(s,data,3)
	if err != nil{
		fmt.Println("Hash Update error: ",err)
	}
	hash,hashLength,err := c.SDFHashFinal(s)
	if err != nil{
		fmt.Println("write file error: ",err)
	}
	fmt.Printf("hash:%x hashLength:%d \n",hash,hashLength)

}


func TestReleasePrivateKeyAccessRight(t *testing.T) {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err:=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()
	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err:=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	key,keyHandle,err := c.SDFGenerateKeyWithIPK_ECC(s,1,256)
	if err != nil {
		fmt.Println("SDFGenerateKeyWithIPK_ECC",err)
	}
	fmt.Println("===SDFGenerateKeyWithIPK_ECC===")
	fmt.Println("keyHandle",keyHandle)
	fmt.Println("Key X ",[]byte(key.X))
	fmt.Println("Key Y ",[]byte(key.Y))
	fmt.Println("Key M ",[]byte(key.M))
	fmt.Println("Key C ",[]byte(key.C))
	fmt.Println("Key L ",key.L)

	fmt.Println("===SDFReleasePrivateKeyAccessRight===")
	err = c.SDFReleasePrivateKeyAccessRight(s,1)
	if err != nil{
		fmt.Println("Release privateKey access right error: ",err)
	}

}


func TestIntECCSign(t *testing.T) {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err:=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err:=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	var publicKey core.ECCrefPublicKey
	var privateKey core.ECCrefPrivateKey
	publicKey,privateKey,err = c.SDFGenerateKeyPair_ECC(s,core.SGD_SM2_3,256)
	fmt.Println("===SDFGenerateKeyPair_ECC===")
	fmt.Println("Public Key Bits",publicKey.Bits)
	fmt.Println("Public Key X",[]byte(publicKey.X))
	fmt.Println("Public Key Y",[]byte(publicKey.Y))
	fmt.Println("private Key Bits",privateKey.Bits)
	fmt.Println("private Key K",[]byte(privateKey.K))

	//假设 inHashData 是32个字节的哈希值
	inHashData := []byte{ 0xbc  ,0xa3  ,0xde  ,0xa1  ,0x2f  ,0x89  ,0xd7  ,0x78  ,0xe5  ,0xb7  ,0x0b  ,0x86  ,0x7d  ,0x1e  ,0x36  ,0x0e  ,0x93  ,0x7d  ,0x47  ,0xcb  ,0xbb  ,0xac  ,0x39  ,0x06 ,0x35 ,0x81  ,0xa4  ,0xe1  ,0x85  ,0x76  ,0x57  ,0x31 }
	fmt.Println("===SDFInternalSign_ECC===")
	signature,err := c.SDFInternalSign_ECC(s,1,inHashData,32)
	if err != nil{
		fmt.Println("Internal sign error: ",err)
	}

	fmt.Println("===SDFInternalVerify_ECC===")
	err = c.SDFInternalVerify_ECC(s,1,inHashData,32,signature)
	if err != nil{
		fmt.Println("Internal verify error: ",err)
	}else {
		fmt.Println("Internal verify succeed! ")
	}

}

func TestIntECCEnc(t *testing.T) {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err:=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err:=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	var publicKey core.ECCrefPublicKey
	var privateKey core.ECCrefPrivateKey
	publicKey,privateKey,err = c.SDFGenerateKeyPair_ECC(s,core.SGD_SM2_3,256)
	fmt.Println("===SDFGenerateKeyPair_ECC===")
	fmt.Println("Public Key Bits",publicKey.Bits)
	fmt.Println("Public Key X",[]byte(publicKey.X))
	fmt.Println("Public Key Y",[]byte(publicKey.Y))
	fmt.Println("private Key Bits",privateKey.Bits)
	fmt.Println("private Key K",[]byte(privateKey.K))

	//假设 inHashData 是32个字节的哈希值
	inHashData := []byte{ 0xbc  ,0xa3  ,0xde  ,0xa1  ,0x2f  ,0x89  ,0xd7  ,0x78  ,0xe5  ,0xb7  ,0x0b  ,0x86  ,0x7d  ,0x1e  ,0x36  ,0x0e  ,0x93  ,0x7d  ,0x47  ,0xcb  ,0xbb  ,0xac  ,0x39  ,0x06 ,0x35 ,0x81  ,0xa4  ,0xe1  ,0x85  ,0x76  ,0x57  ,0x31 }
	fmt.Println("===SDFInternalEncrypt_ECC===")
	fmt.Printf("plain data %x ,dataLength %d  \n",inHashData,len(inHashData))
	encData,err:=c.SDFInternalEncrypt_ECC(s,1,core.SGD_SM2_3,inHashData,32)
	if err != nil{
		fmt.Println("Internal encrypt error: ",err)
	}

	fmt.Println("===SDFInternalDecrypt_ECC===")
	data,dataLength,err:=c.SDFInternalDecrypt_ECC(s,1,core.SGD_SM2_3,encData)
	if err != nil{
		fmt.Println("Internal decrypt error: ",err)
	}
	fmt.Printf("decrypted data %x  ,dataLength %d \n ",data,dataLength)


}

func TestExtECCSign(t *testing.T) {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err:=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err:=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	var publicKey core.ECCrefPublicKey
	var privateKey core.ECCrefPrivateKey
	publicKey,privateKey,err = c.SDFGenerateKeyPair_ECC(s,core.SGD_SM2_1,256)
	fmt.Println("===SDFGenerateKeyPair_ECC===")
	fmt.Println("Public Key Bits",publicKey.Bits)
	fmt.Println("Public Key X",[]byte(publicKey.X))
	fmt.Println("Public Key Y",[]byte(publicKey.Y))
	fmt.Println("private Key Bits",privateKey.Bits)
	fmt.Println("private Key K",[]byte(privateKey.K))

	fmt.Println("===SDFExternalSign_ECC===")
	inputData := []byte{ 0xbc  ,0xa3  ,0xde  ,0xa1  ,0x2f  ,0x89  ,0xd7  ,0x78  ,0xe5  ,0xb7  ,0x0b  ,0x86  ,0x7d  ,0x1e  ,0x36  ,0x0e  ,0x93  ,0x7d  ,0x47  ,0xcb  ,0xbb  ,0xac  ,0x39  ,0x06 ,0x35 ,0x81  ,0xa4  ,0xe1  ,0x85  ,0x76  ,0x57  ,0x31 }
	fmt.Printf("plain data %x \n",inputData)
	signData,err :=c.SDFExternalSign_ECC(s,core.SGD_SM2_1,privateKey,inputData,32)
	if err != nil{
		fmt.Println( "External Sign error: ",err)
	}
	fmt.Printf("signData R %x \n",[]byte(signData.R))
	fmt.Printf("signData S %x \n",[]byte(signData.S))

	fmt.Println("===SDFExternalVerify_ECC===")
	err=c.SDFExternalVerify_ECC(s,core.SGD_SM2_1,publicKey,inputData,32,signData)
	if err != nil{
		fmt.Println("External Verify error: ",err)
	}else {
		fmt.Println("External verify succeed! ")
	}


}

func TestExtECCEnc(t *testing.T) {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err:=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err:=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	var publicKey core.ECCrefPublicKey
	var privateKey core.ECCrefPrivateKey
	publicKey,privateKey,err = c.SDFGenerateKeyPair_ECC(s,core.SGD_SM2_2,256)
	fmt.Println("===SDFGenerateKeyPair_ECC===")
	fmt.Println("Public Key Bits",publicKey.Bits)
	fmt.Println("Public Key X",[]byte(publicKey.X))
	fmt.Println("Public Key Y",[]byte(publicKey.Y))
	fmt.Println("private Key Bits",privateKey.Bits)
	fmt.Println("private Key K",[]byte(privateKey.K))

	inputData := []byte{ 0xbc  ,0xa3  ,0xde  ,0xa1  ,0x2f  ,0x89  ,0xd7  ,0x78  ,0xe5  ,0xb7  ,0x0b  ,0x86  ,0x7d  ,0x1e  ,0x36  ,0x0e  ,0x93  ,0x7d  ,0x47  ,0xcb  ,0xbb  ,0xac  ,0x39  ,0x06 ,0x35 ,0x81  ,0xa4  ,0xe1  ,0x85  ,0x76  ,0x57  ,0x31 }
	fmt.Printf("plain data%x \n",inputData)
	fmt.Println("===SDFExternalEncrypt_ECC===")
	encData,err := c.SDFExternalEncrypt_ECC(s,core.SGD_SM2_2,publicKey,inputData,32)
	if err != nil{
		fmt.Println("External Encrypt  error: ",err)
	}

	fmt.Println("===SDFExternalDecrypt_ECC===")
	decData,decDataLength,err := c.SDFExternalDecrypt_ECC(s,core.SGD_SM2_2,privateKey,encData)
	if err != nil{
		fmt.Println("External Decrypt  error: ",err)
	}
	fmt.Printf("decrypt data %x decrypt data length %d \n",decData,decDataLength)
}

func TestGenerateECCFunc(t *testing.T) {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err:=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err:=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	fmt.Println("===SDFGenerateKeyWithIPK_ECC===")
	key,keyHandle,err := c.SDFGenerateKeyWithIPK_ECC(s,1,256)
	if err != nil {
		fmt.Println("SDFGenerateKeyWithIPK_ECC",err)
	}
	fmt.Println("keyHandle",keyHandle)
	fmt.Println("Key X ",[]byte(key.X))
	fmt.Println("Key Y ",[]byte(key.Y))
	fmt.Println("Key M ",[]byte(key.M))
	fmt.Println("Key C ",[]byte(key.C))
	fmt.Println("Key L ",key.L)

	fmt.Println("===SDFExportEncPublicKey_ECC===")
	publicKey,err:=c.SDFExportEncPublicKey_ECC(s,1)
	if err != nil{
		fmt.Println("Export EncPublicKey error: ",err)
	} else{
		fmt.Println("Public Key Bits",publicKey.Bits)
		fmt.Println("Public Key X",[]byte(publicKey.X))
		fmt.Println("Public Key Y",[]byte(publicKey.Y))

		key1,keyHandle1,err := c.SDFGenerateKeyWithEPK_ECC(s,256,core.SGD_SM2_2,publicKey)
		if err != nil{
			fmt.Println("SDFGenerateKeyWithEPK RSA error: ",err)
		}
		fmt.Println("===SDFGenerateKeyWithEPK_ECC===")
		fmt.Println("Public Key X",[]byte(key1.X))
		fmt.Println("Public Key Y",[]byte(key1.Y))
		fmt.Println("Public Key M",[]byte(key1.M))
		fmt.Println("keyHandle1 ",keyHandle1)
	}

}

func TestEncryptFunc(t *testing.T) {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err:=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err:=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	var length uint = 32
	randomNum,err:=c.SDFGenerateRandom(s,length)
	if err != nil{
		fmt.Println("generate random error: ",err)
	}
	fmt.Println("random number for key: ",randomNum)

	keyHandle,err :=c.SDFImportKey(s,randomNum,32)
	if err != nil{
		fmt.Println("Import key error: ",err)
	}

	//iv任意取
	iv :=[]byte{ 0xd0,0x4e ,0x51 ,0xcd ,0xb1 ,0x3c ,0x4a ,0xda ,0x34 ,0x72 ,0x44 ,0xc3 ,0x53 ,0x29 ,0x06 ,0x24 }
	inData:= []byte{ 0xbc  ,0xa3  ,0xde  ,0xa1  ,0x2f  ,0x89  ,0xd7  ,0x78  ,0xe5  ,0xb7  ,0x0b  ,0x86  ,0x7d  ,0x1e  ,0x36  ,0x0e  ,0x93  ,0x7d  ,0x47  ,0xcb  ,0xbb  ,0xac  ,0x39  ,0x06 ,0x35 ,0x81  ,0xa4  ,0xe1  ,0x85  ,0x76  ,0x57  ,0x31 }
	fmt.Printf("inData:%x inDataLength:%d \n",inData,len(inData))

	//SGD_SMS4_ECB正確但是SGD_SMS4_CBC验证失败
	encData,encDataLength,err :=c.SDFEncrypt(s,keyHandle,core.SGD_SMS4_ECB,iv,inData,uint(len(inData)))
	if err != nil{
		fmt.Println("Encrypt data error: ",err)
	}
	fmt.Printf("encData:%x encDataLength:%d \n",encData,encDataLength)

	data,dataLength,err :=c.SDFDecrypt(s,keyHandle,core.SGD_SMS4_ECB,iv,encData,encDataLength)
	if err != nil{
		fmt.Println("Decrypt data error: ",err)
	}
	fmt.Printf("data:%x dataLength:%d \n",data,dataLength)

	err=c.SDFDestroyKey(s,keyHandle)
	if err != nil{
		fmt.Println("Destroy key error: ",err)
	}

}

func TestSDFMAC(t *testing.T) {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err:=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err:=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()
	fmt.Println("===SDFGenerateRandom===")
	var length uint = 16
	randomNum,err:=c.SDFGenerateRandom(s,length)
	if err != nil{
		fmt.Println("generate random error: ",err)
	}
	fmt.Println("random number for key: ",randomNum)

	fmt.Println("===SDFImportKey===")
	keyHandle,err :=c.SDFImportKey(s,randomNum,16)
	if err != nil{
		fmt.Println("Import key error: ",err)
	}

	//iv任意取
	fmt.Println("===SDFCalculateMAC===")
	iv :=[]byte{ 0xd0,0x4e ,0x51 ,0xcd ,0xb1 ,0x3c ,0x4a ,0xda ,0x34 ,0x72 ,0x44 ,0xc3 ,0x53 ,0x29 ,0x06 ,0x24 }
	mac,macLength,err :=c.SDFCalculateMAC(s,keyHandle,core.SGD_SMS4_MAC,iv,randomNum,uint(len(randomNum)))
	if err != nil{
		fmt.Println("Decrypt data error: ",err)
	}
	fmt.Printf("mac:%x macLength:%d \n",mac,macLength)

	fmt.Println("===SDFDestroyKey===")
	err=c.SDFDestroyKey(s,keyHandle)
	if err != nil{
		fmt.Println("Destroy key error: ",err)
	}
}


func TestFilesFunc(t *testing.T) {
	c:=New(libPath())
	d,err :=c.SDFOpenDevice()
	if err != nil{
		fmt.Println("open device error: ",err)
	}
	defer func() {
		err=c.SDFCloseDevice(d)
		if err != nil{
			fmt.Println("close device error: ",err)
		}
	}()
	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}
	defer func(){
		err=c.SDFCloseSession(s)
		if err != nil{
			fmt.Println("close session error: ",err)
		}
	}()

	fmt.Println("===SDFGenerateRandom===")
	randomNum,err:=c.SDFGenerateRandom(s,32)
	if err != nil{
		fmt.Println("generate random error: ",err)
	}
	fmt.Printf("randomNum: %x randomNumLength: %d \n",randomNum,32)

	fmt.Println("===SDFCreateFile===")
	err =c.SDFCreateFile(s,[]byte("test"),32)
	if err != nil{
		fmt.Println("create file error: ",err)
	}

	fmt.Println("===SDFWriteFile===")
	err =c.SDFWriteFile(s,[]byte("test"),0 ,randomNum,32)
	if err != nil{
		fmt.Println("write file error: ",err)
	}


	fmt.Println("===SDFReadFile===")
	var readLength int = len(randomNum)
	readbuffer,readLength1,err :=c.SDFReadFile(s,[]byte("test"),0,uint(readLength)  )
	if err != nil{
		fmt.Println("read file error: ",err)
	}
	fmt.Printf("readbuffer: %x readLength: %d \n",readbuffer,readLength1)

	fmt.Println("===SDFDeleteFile===")
	err =c.SDFDeleteFile(s,[]byte("test"))
	if err != nil{
		fmt.Println("delete file error: ",err)
	}

}




