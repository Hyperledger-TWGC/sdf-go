package sdf

import (
	"fmt"
	"github.com/yzwskyspace/sdf/core"
	"os"
	"runtime"
	"testing"
)


func libPath() string{
	wd,_ := os.Getwd()
	if runtime.GOOS=="windows"{
		return wd+"\\sansec\\Win\\64\\swsds.dll"
	}else {
		return wd+"/sansec/Linux/64/libswsds.so"
	}
}

//  BasicFuncTest
func TestBasicFunc(t *testing.T) {

	var c *Ctx
	c=New(libPath())

	var err error
	var deviceHandle  DeviceHandleType
	d,err :=c.SDFOpenDevice(deviceHandle)
	if err != nil{
	fmt.Println("open device error: ",err)
	}
	s,err :=c.SDFOpenSession(d)
	if err != nil{
	fmt.Println("open session error: ",err)
	}

	var length uint = 16
	by,err:=c.SDFGenerateRandom(s,length)
	if err != nil{
		fmt.Println("generate random error: ",err)
	}
	fmt.Println("random: ",by)

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

	err =c.SDFCloseSession(s)
	if err != nil{
		fmt.Println("close session error: ",err)
	}
	err =c.SDFCloseDevice(d)
	if err != nil{
		fmt.Println("close device error: ",err)
	}
}

// RSAFuncTest
func TestRSAFunc(t *testing.T) {

	var c *Ctx
	c=New(libPath())

	var err error
	var deviceHandle  DeviceHandleType
	d,err :=c.SDFOpenDevice(deviceHandle)
	if err != nil{
		fmt.Println("open device error: ",err)
	}

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}

	var public core.RSArefPublicKey
	var private core.RSArefPrivateKey
	public,private,err = c.SDFGenerateKeyPair_RSA(s,512)
	fmt.Println("===SDFGenerateKeyPair_RSA===")
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

	var signPublicKey core.RSArefPublicKey
	signPublicKey,err = c.SDFExportSignPublicKey_RSA(s,1)
	fmt.Println("===SDFExportSignPublicKey_RSA===")
	fmt.Println("SignPublicKey Key Bits",signPublicKey.Bits)
	fmt.Println("SignPublicKey Key M",[]byte(signPublicKey.M))
	fmt.Println("SignPublicKey Key E",[]byte(signPublicKey.E))

	var encPublicKey core.RSArefPublicKey
	encPublicKey,err = c.SDFExportEncPublicKey_RSA(s,1)
	fmt.Println("===SDFExportEncPublicKey_RSA===")
	fmt.Println("EncPublicKey Key Bits",encPublicKey.Bits)
	fmt.Println("EncPublicKey Key M",[]byte(encPublicKey.M))
	fmt.Println("EncPublicKey Key E",[]byte(encPublicKey.E))

	var length uint = 256
	randNum,err:=c.SDFGenerateRandom(s,length)
	if err != nil{
		fmt.Println("generate random error: ",err)
	}

	dataOutput,err:=c.SDFInternalPrivateKeyOperation_RSA(s,1,randNum,signPublicKey.Bits/8)
	if err != nil{
		fmt.Println("InternalPrivateKey RSA error: ",err)
	}
	fmt.Println("===SDFInternalPrivateKeyOperation_RSA===")
	fmt.Println("DataOutput ",dataOutput)

	dataOutput1,err := c.SDFInternalPublicKeyOperation_RSA(s,1,dataOutput,(uint)(len(dataOutput)))
	if err != nil{
		fmt.Println("InternalPublicKey RSA error: ",err)
	}
	fmt.Println("===SDFInternalPublicKeyOperation_RSA===")
	fmt.Println("DataOutput ",dataOutput1)

	err =c.SDFCloseSession(s)
	if err != nil{
		fmt.Println("close session error: ",err)
	}
	err =c.SDFCloseDevice(d)
	if err != nil{
		fmt.Println("close device error: ",err)
	}
}

func TestGenerateRSAFunc(t *testing.T) {

	var c *Ctx
	c=New(libPath())

	var err error
	var deviceHandle  DeviceHandleType
	d,err :=c.SDFOpenDevice(deviceHandle)
	if err != nil{
		fmt.Println("open device error: ",err)
	}

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}

	key,keyLength,keyHandle,err := c.SDFGenerateKeyWithIPK_RSA(s,1,256)
	if err != nil {
		fmt.Println("SDFGenerateKeyWithIPK_RSA",err)
	}
	fmt.Println("===SDFGenerateKeyWithIPK_RSA===")
	fmt.Println("key ",key,"keyLength ",keyLength,keyHandle)

	publicKey,err:=c.SDFExportEncPublicKey_RSA(s,1)
	if err != nil{
		fmt.Println("Export EncPublicKey error: ",err)
	} else{
		fmt.Println("===SDFExportEncPublicKey_RSA===")
		fmt.Println("Public Key Bits",publicKey.Bits)
		fmt.Println("Public Key M",[]byte(publicKey.M))
		fmt.Println("Public Key E",[]byte(publicKey.E))


		key1,keyLength1,keyHandle1,err := c.SDFGenerateKeyWithEPK_RSA(s,1,publicKey)
		if err != nil{
			fmt.Println("SDFGenerateKeyWithEPK RSA error: ",err)
		}
		fmt.Println("===SDFGenerateKeyWithEPK_RSA===")
		fmt.Println("key1 ",key1,"keyLength1 ",keyLength1,keyHandle1)
	}

	err =c.SDFCloseSession(s)
	if err != nil{
		fmt.Println("close session error: ",err)
	}
	err =c.SDFCloseDevice(d)
	if err != nil{
		fmt.Println("close device error: ",err)
	}
}

func TestReleasePrivateKeyAccessRight(t *testing.T) {

	var c *Ctx
	c=New(libPath())

	var err error
	var deviceHandle  DeviceHandleType
	d,err :=c.SDFOpenDevice(deviceHandle)
	if err != nil{
		fmt.Println("open device error: ",err)
	}

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}

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

	//password:= []byte{ 0xbc  ,0xa3  ,0xde  ,0xa1  ,0x2f  ,0x89  ,0xd7  ,0x78  ,0xe5  ,0xb7  ,0x0b  ,0x86  ,0x7d  ,0x1e  ,0x36  ,0x0e  ,0x93  ,0x7d  ,0x47  ,0xcb  ,0xbb  ,0xac  ,0x39  ,0x06 ,0x35 ,0x81  ,0xa4  ,0xe1  ,0x85  ,0x76  ,0x57  ,0x31 }

	fmt.Println("===SDFGetPrivateKeyAccessRight===")
	//err = c.SDFGetPrivateKeyAccessRight(s,2,password,32)
	//if err != nil{
	//	fmt.Println("Get privateKey access right error: ",err)
	//}

	fmt.Println("===SDFReleasePrivateKeyAccessRight===")
	err = c.SDFReleasePrivateKeyAccessRight(s,1)
	if err != nil{
		fmt.Println("Release privateKey access right error: ",err)
	}

	err =c.SDFCloseSession(s)
	if err != nil{
		fmt.Println("close session error: ",err)
	}
	err =c.SDFCloseDevice(d)
	if err != nil{
		fmt.Println("close device error: ",err)
	}
}

// RSAFuncTest
func TestECCFunc(t *testing.T) {

	var c *Ctx
	c=New(libPath())

	var err error
	var deviceHandle  DeviceHandleType
	d,err :=c.SDFOpenDevice(deviceHandle)
	if err != nil{
		fmt.Println("open device error: ",err)
	}

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}

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

	fmt.Println("===SDFInternalEncrypt_ECC===")
	fmt.Printf("plain data%x ",inHashData)
	encData,err:=c.SDFInternalEncrypt_ECC(s,1,core.SGD_SM2_3,inHashData,32)
	if err != nil{
		fmt.Println("Internal encrypt error: ",err)
	}

	data,dataLength,err:=c.SDFInternalDecrypt_ECC(s,1,core.SGD_SM2_3,encData)
	if err != nil{
		fmt.Println("Internal decrypt error: ",err)
	}
	fmt.Printf("decrypted data %x  ,dataLength %d ",data,dataLength)


	var signPublicKey core.ECCrefPublicKey
	signPublicKey,err = c.SDFExportSignPublicKey_ECC(s,1)
	fmt.Println("===SDFExportSignPublicKey_ECC===")
	fmt.Println("SignPublic Key Bits",signPublicKey.Bits)
	fmt.Println("SignPublic Key X",[]byte(signPublicKey.X))
	fmt.Println("SignPublic Key Y",[]byte(signPublicKey.Y))

	var encPublicKey core.ECCrefPublicKey
	encPublicKey,err = c.SDFExportEncPublicKey_ECC(s,1)
	fmt.Println("===SDFExportEncPublicKey_ECC===")
	fmt.Println("EncPublic Key Bits",encPublicKey.Bits)
	fmt.Println("EncPublic Key X",[]byte(encPublicKey.X))
	fmt.Println("EncPublic Key Y",[]byte(encPublicKey.Y))


	fmt.Printf("plain data%x ",data)
	fmt.Println("===SDFExternalEncrypt_ECC===")
	encData1,err := c.SDFExternalEncrypt_ECC(s,core.SGD_SM2_3,encPublicKey,data,dataLength)
	if err != nil{
		fmt.Println("External Encrypt  error: ",err)
	}
	fmt.Printf("encrypt data %x ",encData1)

	var data1 []byte
	var dataLength1 uint
	fmt.Println("===SDFExternalDecrypt_ECC===")
	data1,dataLength1,err=c.SDFExternalDecrypt_ECC(s,core.SGD_SM2_3,privateKey,encData1)
	if err != nil{
		fmt.Println("External Decrypt  error: ",err)
	}
	fmt.Printf("decrypted data %x  ,dataLength %d ",data1,dataLength1)

	err =c.SDFCloseSession(s)
	if err != nil{
		fmt.Println("close session error: ",err)
	}
	err =c.SDFCloseDevice(d)
	if err != nil{
		fmt.Println("close device error: ",err)
	}
}

func TestGenerateECCFunc(t *testing.T) {

	var c *Ctx
	c=New(libPath())

	var err error
	var deviceHandle  DeviceHandleType
	d,err :=c.SDFOpenDevice(deviceHandle)
	if err != nil{
		fmt.Println("open device error: ",err)
	}

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}


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

	publicKey,err:=c.SDFExportEncPublicKey_ECC(s,1)
	if err != nil{
		fmt.Println("Export EncPublicKey error: ",err)
	} else{
		fmt.Println("===SDFExportEncPublicKey_ECC===")
		fmt.Println("Public Key Bits",publicKey.Bits)
		fmt.Println("Public Key X",[]byte(publicKey.X))
		fmt.Println("Public Key Y",[]byte(publicKey.Y))

		key1,keyHandle1,err := c.SDFGenerateKeyWithEPK_ECC(s,256,core.SGD_SM2_3,publicKey)
		if err != nil{
			fmt.Println("SDFGenerateKeyWithEPK RSA error: ",err)
		}
		fmt.Println("===SDFGenerateKeyWithEPK_ECC===")
		fmt.Println("Public Key X",[]byte(key1.X))
		fmt.Println("Public Key Y",[]byte(key1.Y))
		fmt.Println("Public Key M",[]byte(key1.M))
		fmt.Println("keyHandle1 ",keyHandle1)
	}

	err =c.SDFCloseSession(s)
	if err != nil{
		fmt.Println("close session error: ",err)
	}
	err =c.SDFCloseDevice(d)
	if err != nil{
		fmt.Println("close device error: ",err)
	}
}

func TestSDFEncrypt(t *testing.T) {

	var c *Ctx
	c=New(libPath())

	var err error
	var deviceHandle  DeviceHandleType
	d,err :=c.SDFOpenDevice(deviceHandle)
	if err != nil{
		fmt.Println("open device error: ",err)
	}

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}

	var length uint = 16
	by,err:=c.SDFGenerateRandom(s,length)
	if err != nil{
		fmt.Println("generate random error: ",err)
	}
	fmt.Println("random number for key: ",by)

	keyHandle,err :=c.SDFImportKey(s,by,16)
	if err != nil{
		fmt.Println("Import key error: ",err)
	}
	fmt.Println("keyHandle",keyHandle)

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



	err =c.SDFCloseSession(s)
	if err != nil{
		fmt.Println("close session error: ",err)
	}

	err =c.SDFCloseDevice(d)
	if err != nil{
		fmt.Println("close device error: ",err)
	}
}

func TestSDFMAC(t *testing.T) {

	var c *Ctx
	c=New(libPath())

	var err error
	var deviceHandle  DeviceHandleType
	d,err :=c.SDFOpenDevice(deviceHandle)
	if err != nil{
		fmt.Println("open device error: ",err)
	}

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}

	var length uint = 16
	by,err:=c.SDFGenerateRandom(s,length)
	if err != nil{
		fmt.Println("generate random error: ",err)
	}
	fmt.Println("random number for key: ",by)

	keyHandle,err :=c.SDFImportKey(s,by,16)
	if err != nil{
		fmt.Println("Import key error: ",err)
	}
	fmt.Println("keyHandle",keyHandle)

	//iv任意取
	iv :=[]byte{ 0xd0,0x4e ,0x51 ,0xcd ,0xb1 ,0x3c ,0x4a ,0xda ,0x34 ,0x72 ,0x44 ,0xc3 ,0x53 ,0x29 ,0x06 ,0x24 }

	mac,macLength,err :=c.SDFCalculateMAC(s,keyHandle,core.SGD_SMS4_MAC,iv,by,uint(len(by)))
	if err != nil{
		fmt.Println("Decrypt data error: ",err)
	}
	fmt.Printf("mac:%x macLength:%d \n",mac,macLength)


	err=c.SDFDestroyKey(s,keyHandle)
	if err != nil{
		fmt.Println("Destroy key error: ",err)
	}



	err =c.SDFCloseSession(s)
	if err != nil{
		fmt.Println("close session error: ",err)
	}

	err =c.SDFCloseDevice(d)
	if err != nil{
		fmt.Println("close device error: ",err)
	}
}


func TestSDFFiles(t *testing.T) {

	var c *Ctx
	c=New(libPath())

	var err error
	var deviceHandle  DeviceHandleType
	d,err :=c.SDFOpenDevice(deviceHandle)
	if err != nil{
		fmt.Println("open device error: ",err)
	}

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}

	err =c.SDFCreateFile(s,[]byte("yzw"),1024)
	if err != nil{
		fmt.Println("create file error: ",err)
	}

	//writebuffer:=[]byte{ 0xbc  ,0xa3  ,0xde  ,0xa1  ,0x2f  ,0x89  ,0xd7  ,0x78  ,0xe5  ,0xb7  ,0x0b  ,0x86  ,0x7d  ,0x1e  ,0x36  ,0x0e  ,0x93  ,0x7d  ,0x47  ,0xcb  ,0xbb  ,0xac  ,0x39  ,0x06 ,0x35 ,0x81  ,0xa4  ,0xe1  ,0x85  ,0x76  ,0x57  ,0x31 }
	//fmt.Printf("writebuffer:%x writeLength:%d \n",writebuffer,32)
	//err =c.SDFWriteFile(s,[]byte("yzw"),0 ,[]byte{'1','2'})
	//if err != nil{
	//	fmt.Println("write file error: ",err)
	//}
	//
	//readbuffer,readLength,err :=c.SDFReadFile(s,[]byte("yzw"),0 )
	//if err != nil{
	//	fmt.Println("write file error: ",err)
	//}
	//fmt.Printf("readbuffer:%x readLength:%d \n",readbuffer,readLength)

	err =c.SDFDeleteFile(s,[]byte("yzw"))
	if err != nil{
		fmt.Println("delete file error: ",err)
	}

	err =c.SDFCloseSession(s)
	if err != nil{
		fmt.Println("close session error: ",err)
	}
	err =c.SDFCloseDevice(d)
	if err != nil{
		fmt.Println("close device error: ",err)
	}
}

func TestSDFhash(t *testing.T) {
	var c *Ctx
	c=New(libPath())

	var err error
	var deviceHandle  DeviceHandleType
	d,err :=c.SDFOpenDevice(deviceHandle)
	if err != nil{
		fmt.Println("open device error: ",err)
	}

	s,err :=c.SDFOpenSession(d)
	if err != nil{
		fmt.Println("open session error: ",err)
	}

	var length uint = 16
	by,err:=c.SDFGenerateRandom(s,length)
	if err != nil{
		fmt.Println("generate random error: ",err)
	}
	fmt.Println("random number for key: ",by)

	_,err=c.SDFHashInit(s,core.SGD_SM3,nil,0)
	if err != nil{
		fmt.Println("Hash init error: ",err)
	}

	err = c.SDFHashUpdate(s,by,length)
	if err != nil{
		fmt.Println("Hash Update error: ",err)
	}

	hash,hashLength,err := c.SDFHashFinal(s)
	if err != nil{
		fmt.Println("write file error: ",err)
	}
	fmt.Printf("hash:%x hashLength:%d \n",hash,hashLength)

	err =c.SDFCloseSession(s)
	if err != nil{
		fmt.Println("close session error: ",err)
	}
	err =c.SDFCloseDevice(d)
	if err != nil{
		fmt.Println("close device error: ",err)
	}
}


func TestString(t *testing.T) {
	a:=[]byte{0x11,0x02,0x03}
	b:=string(a)
	//test,_:=hex.DecodeString(b)
	fmt.Println(b[0],a[0])
	//a:=[]byte("hello")
	//b:=string(a)
	//fmt.Println(b[1],len(b))

	//a:=[]byte{0x11,0x01}
	//fmt.Println(a[1])
	//b:=hex.EncodeToString(a)
	//fmt.Println(b)
	//c,_:=hex.DecodeString(b)
	//fmt.Println(c)

}