package core

/*
#cgo windows CFLAGS: -DPACKED_STRUCTURES
#cgo linux LDFLAGS: -ldl
#cgo darwin LDFLAGS: -ldl

#include"type.h"
*/
import "C"

//var stubData = []byte{0}
//// cMessage returns the pointer/length pair corresponding to data.
//func CMessage(data []byte) (dataPtr C.SGD_UCHAR_PRT) {
//	l := len(data)
//	if l == 0 {
//		// &data[0] is forbidden in this case, so use a nontrivial array instead.
//		data = stubData
//	}
//	return C.SGD_UCHAR_PRT(unsafe.Pointer(&data[0]))
//}

