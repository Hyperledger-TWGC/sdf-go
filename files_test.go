package sdf

import (
	"fmt"
	"testing"
)

func TestFilesFunc(t *testing.T) {
	c, d, s := Connect(t)
	defer Release(t, c, d, s)

	fmt.Println("===SDFGenerateRandom===")
	var dataLength uint = 32
	randomNum, err := c.SDFGenerateRandom(s, dataLength)
	if err != nil {
		fmt.Println("generate random error: ", err)
	}
	fmt.Printf("randomNum: %x randomNumLength: %d \n", randomNum, dataLength)

	fmt.Println("===SDFCreateFile===")
	err = c.SDFCreateFile(s, []byte("test"), 64)
	if err != nil {
		fmt.Println("create file error: ", err)
	}

	fmt.Println("===SDFWriteFile===")
	err = c.SDFWriteFile(s, []byte("test"), 0, randomNum, 32)
	if err != nil {
		fmt.Println("write file error: ", err)
	}

	fmt.Println("===SDFReadFile===")
	var readLength int = len(randomNum)
	readbuffer, readLength1, err := c.SDFReadFile(s, []byte("test"), 0, uint(readLength))
	if err != nil {
		fmt.Println("read file error: ", err)
	}
	fmt.Printf("readbuffer: %x readLength: %d \n", readbuffer, readLength1)

	fmt.Println("===SDFDeleteFile===")
	err = c.SDFDeleteFile(s, []byte("test"))
	if err != nil {
		fmt.Println("delete file error: ", err)
	}

}
