package interfaces

type KeySerialization interface {
	Serialize() ([]byte, error)
	Deserialize([]byte) (KeyBase, error)
	GenerateKey() (KeyBase, error)
	//IsSymmetric() bool
	//IsMidstream() bool
}

type KeyEncryptDecrypt interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

type KeyMAC interface {
	Write([]byte) (int, error)
	Sum([]byte) ([]byte, error)
	Verify([]byte) (bool, error)
	Reset()
}

type KeyBase interface {
	KeySerialization
	CanEncrypt() bool
	CanDecrypt() bool
}

type KeySymmetric interface {
	KeyBase
	GetKey() []byte
}

type KeyPublic interface {
	EncryptAsym([]byte) ([]byte, error)
}

type KeyPrivate interface {
	DecryptAsym([]byte) ([]byte, error)
}

type KeyAsymmetric interface {
	KeyBase
	GetPublicKey() KeyPublic
	GetPrivateKey() KeyPrivate
}
