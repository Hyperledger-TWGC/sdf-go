package sdf


import (
	"fmt"
	"github.com/yzwskyspace/sdf/core"
	"os"
	"testing"
)


func TestOpenDevice(t *testing.T) {
	wd,_ := os.Getwd()
	lib := wd+"/sansec/Linux/64/libswsds.so"
	var c *Ctx
	c=New(lib)

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


func TestGetPrivateKeyAccessRight(t *testing.T) {

	wd,_ := os.Getwd()
	lib := wd+"/sansec/Linux/64/libswsds.so"
	var c *Ctx
	c=New(lib)

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

	pucPassword,err :=c.SDFGetPrivateKeyAccessRight(s,1,16)
	if err != nil{
		fmt.Println("get puc password error ",err)
	}
	fmt.Println("private Key: ",pucPassword)

	err = c.SDFReleasePrivateKeyAccessRight(s,1)
	if err != nil{
		fmt.Println("Release private Key: ",err)
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