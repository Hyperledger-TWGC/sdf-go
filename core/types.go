package core


type DeviceInfo struct {
	IssuerName      string
	DeviceName      string
	DeviceSerial    string
	DeviceVersion   uint
	StandardVersion uint
	AsymAlgAbility  [2]uint
	SymAlgAbility   uint
	HashAlgAbility  uint
	BufferSize      uint
}

type DeviceRunStatus struct {
	Onboot          uint
	Service          uint
	Concurrency          uint
	Memtotal          uint
	Memfree          uint
	Cpu          uint
	Reserve1          uint
	Reserve2          uint
}

type RSArefPublicKeyLite struct {
	Bits   uint
	M    string
	E    string
}

type RSArefPrivateKeyLite struct {
	Bits          uint
	M             string
	E             string
	D             string
	Prime         [2]string
	Pexp          [2]string
	Coef          string
}

type RSArefPublicKey struct {
	Bits          uint
	M             string
	E             string
}

type RSArefPrivateKey struct {
	Bits          uint
	M             string
	E             string
	D             string
	Prime         [2]string
	Pexp          [2]string
	Coef          string
}

type ECCrefPublicKey struct {
	Bits          uint
	X    string
	Y    string
}

type ECCrefPrivateKey struct {
	Bits          uint
	K    string
}

type  ECCCipher struct {
	X    string
	Y    string
	M    string
	L    uint
	C    string
}

type ECCSignature struct {
	R    string
	S    string
}

type SM9refSignMasterPrivateKey struct {
	Bits          uint
	S    string
}

type SM9refSignMasterPublicKey struct {
	Bits          uint
	Xa    string
	Xb    string
	Ya    string
	Yb    string
}

type SM9refEncMasterPrivateKey struct {
	Bits          uint
	S             string
}

type SM9refEncMasterPublicKey struct {
	Bits          uint
	X    string
	Y    string
}

type SM9refSignUserPrivateKey struct {
	Bits          uint
	X    string
	Y    string
}

type SM9refEncUserPrivateKey struct {
	Bits          uint
	Xa    string
	Xb    string
	Ya    string
	Yb    string
}

type SM9Signature struct {
	H    string
	X    string
	Y    string
}

type SM9Cipher struct {
	X    string
	Y    string
	H    string
	L    uint
	C    string
}

type SM9refKeyPackage struct {
	X    string
	Y    string
}