package other

import (
	"fmt"
	"io/ioutil"
	"testing"
)

func TestStr(t *testing.T) {

	by,err:=ioutil.ReadFile("const.txt")
	if err != nil{
		fmt.Println("error")
	}


	length:=len(by)

	var strSlice []byte
	for i:=0 ; i<length;i++ {
		if i<length && by[i]=='#'{
			strSlice=append(strSlice, '\n')
			for by[i]!=' ' && i<length{
				i++
			}
		}
		if i+2<length  && by[i]=='S' && by[i+1] == 'G' && by[i+2] == 'D' {
			for i<length && by[i]!=' ' && by[i]!=by[16]{
			//	fmt.Println(string(by[i]))
				strSlice=append(strSlice, by[i])
				i++
			}
			strSlice=append(strSlice, ' ')
			strSlice=append(strSlice, '=')
			strSlice=append(strSlice, ' ')

		}

		if i+9<length &&by[i] == '0' && by[i+1] =='x' {
			for i<length && by[i]!=' ' && by[i]!=by[28]{
				strSlice=append(strSlice, by[i])
				i++
			}
			i--
		}



	}
	//fmt.Println(string(strSlice))

	size := len(strSlice)
	var errSlice1 []byte
	var errSlice2 []byte
	for i:=0;i<size;i++{
		if i+2<size  && strSlice[i]=='S' && strSlice[i+1] == 'G' && strSlice[i+2] == 'D' {
			for i<size && strSlice[i]!=' ' {
				//	fmt.Println(string(by[i]))
				errSlice1=append(errSlice1, strSlice[i])
				i++
			}
			errSlice1=append(errSlice1, ' ')

		}
	}

	for i:=0;i<size;i++{
		if i+9<size &&strSlice[i] == '0' && strSlice[i+1] =='x' {
			for i<size && strSlice[i]!=strSlice[22] {
				errSlice2=append(errSlice2, strSlice[i])
				i++
			}
			errSlice2=append(errSlice2, ' ')
		}

	}

	fmt.Println(string(errSlice1))
	fmt.Println(string(errSlice2))


	//------------------------------------------//
    var strerror []byte

	var ii int =0
	var jj int = 0
	var errSlize1Size int = len(errSlice1)
	var errSlize2Size int = len(errSlice2)
	//------------------------------------------//

	for ii<errSlize1Size || jj<errSlize2Size {

		if jj+9<errSlize2Size && errSlice2[jj] == '0' && errSlice2[jj+1] =='x' {
			for jj<errSlize2Size && errSlice2[jj]!=' '  {
				strerror=append(strerror, errSlice2[jj])
				jj++
			}
			strerror=append(strerror, ':')
			strerror=append(strerror, ' ')
		}
		jj++

		if errSlice1[ii] =='S' && errSlice1[ii+1] == 'G' && errSlice1[ii+2] == 'D' {
			strerror=append(strerror, '"')
			for ii<errSlize1Size && errSlice1[ii]!=' ' {
				strerror=append(strerror, errSlice1[ii])
				ii++
			}
			strerror=append(strerror, '"')
			strerror=append(strerror, ',')
			strerror=append(strerror, '\n')
		}
		ii++
	}

	fmt.Println(string(strerror))

}
