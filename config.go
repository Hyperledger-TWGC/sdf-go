package sdf

import "C"

//func New(libPath string) *Ctx{
//	if x:=os.Getenv("SDFHSM_CONF");x==""{
//		os.Setenv("SDFHSM_CONF",libPath)
//	}else {
//		libPath = x
//	}
//	c := new(Ctx)
//	c.ctx = C.New(libPath)
//	if c.ctx == nil{
//		return c
//	}
//	return  c
//}