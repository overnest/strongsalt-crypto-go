package x25519

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"

	. "github.com/overnest/strongsalt-crypto-go/interfaces"
	"github.com/overnest/strongsalt-crypto-go/version"
)

const (
	privKeySerialLength = 4
	pubKeySerialLength  = 4

	keyLength       = 32
	versionTypeName = "X25519KeyVersion"
)

/*
** Version
 */

var (
	VERSION_ONE = newX25519KeyVersion("ONE", 1)
	curVersion  = VERSION_ONE
)

type X25519KeyVersion struct {
	Name    string
	Version version.Version
}

func (kv *X25519KeyVersion) GetVersion() version.Version {
	return kv.Version
}

var keyVersionMap map[int32]version.VersionInterface = make(map[int32]version.VersionInterface)

func newX25519KeyVersion(name string, ver int32) *X25519KeyVersion {
	keyVersion := &X25519KeyVersion{name, version.Version(ver)}
	keyVersionMap[ver] = keyVersion
	return keyVersion
}

func init() {
	version.SetClassVersions(versionTypeName, keyVersionMap)
}

/*
** Public Key
 */

type X25519KeyPub struct {
	key *[keyLength]byte
}

func (k *X25519KeyPub) EncryptAsym(plaintext []byte) ([]byte, error) {
	ciphertext, err := box.SealAnonymous(nil, plaintext, k.GetKey(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func (k *X25519KeyPub) Serialize() ([]byte, error) {
	if k.key == nil {
		return nil, fmt.Errorf("cannot serialize nil key")
	}
	return k.key[:], nil
}

func DeserializePub(data []byte) (*X25519KeyPub, error) {
	var key [keyLength]byte
	for i := 0; i < len(key); i++ {
		key[i] = data[i]
	}
	return &X25519KeyPub{key: &key}, nil
}

func (k *X25519KeyPub) GetKey() *[keyLength]byte {
	return k.key
}

/*
** Private Key
 */

type X25519KeyPriv struct {
	key *[keyLength]byte
	pub *X25519KeyPub
}

func (k *X25519KeyPriv) generatePublic() (*X25519KeyPub, error) {
	keySlice, err := curve25519.X25519(k.GetKey()[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	var key [keyLength]byte
	for i := 0; i < len(key); i++ {
		key[i] = keySlice[i]
	}
	return &X25519KeyPub{&key}, nil
}

func (k *X25519KeyPriv) DecryptAsym(ciphertext []byte) ([]byte, error) {
	if k.pub == nil {
		pub, err := k.generatePublic()
		if err != nil {
			return nil, err
		}
		k.pub = pub
	}
	plaintext, ok := box.OpenAnonymous(nil, ciphertext, k.pub.GetKey(), k.GetKey())
	if !ok {
		return nil, fmt.Errorf("X25519 DecryptAsym open box returned false")
	}
	return plaintext, nil
}

func (k *X25519KeyPriv) Serialize() ([]byte, error) {
	if k.key == nil {
		return nil, fmt.Errorf("cannot serialize nil key")
	}
	return k.key[:], nil
}

func DeserializePriv(data []byte) (*X25519KeyPriv, error) {
	var key [keyLength]byte
	for i := 0; i < len(key); i++ {
		key[i] = data[i]
	}
	return &X25519KeyPriv{key: &key}, nil
}

func (k *X25519KeyPriv) GetKey() *[keyLength]byte {
	return k.key
}

/*
** Main
 */

type X25519Key struct {
	version *X25519KeyVersion
	pub     *X25519KeyPub
	priv    *X25519KeyPriv
}

func (k *X25519Key) GenerateKey() (KeyBase, error) {
	pubBytes, privBytes, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := &X25519KeyPub{key: pubBytes}
	priv := &X25519KeyPriv{key: privBytes, pub: pub}

	return &X25519Key{
		pub:     pub,
		priv:    priv,
		version: curVersion,
	}, nil
}

//
// The serialization/deserialization format is as follows:
//
// Version 1:
//  ------------------------------------------------------------------------------
// | version(4 bytes) | priKeyLen(4 bytes) | priKey | pubKeyLen(4 bytes) | pubKey |
//  ------------------------------------------------------------------------------
//
// The public key field is optional. If there is no public key, then the pubKeyLen would be set to 0.
// The private key is optional if SerializePublic is called, in which case privKeyLen is set to 0.
//

func (k *X25519Key) serialize(pubOnly bool) ([]byte, error) {
	ver := version.Serialize(k.version)

	buf := new(bytes.Buffer)
	_, err := buf.Write(ver)
	if err != nil {
		return nil, err
	}

	if pubOnly {
		err = binary.Write(buf, binary.BigEndian, int32(0))
		if err != nil {
			return nil, err
		}
	} else {
		var priv []byte
		if k.priv != nil {
			priv, err = k.priv.Serialize()
			if err != nil {
				return nil, err
			}
		}
		err = binary.Write(buf, binary.BigEndian, int32(len(priv)))
		if err != nil {
			return nil, err
		}
		_, err = buf.Write(priv)
		if err != nil {
			return nil, err
		}
	}

	var pub []byte
	if k.pub != nil {
		pub, err = k.pub.Serialize()
		if err != nil {
			return nil, err
		}
	}
	err = binary.Write(buf, binary.BigEndian, int32(len(pub)))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(pub)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (k *X25519Key) Serialize() ([]byte, error) {
	return k.serialize(false)
}

func (k *X25519Key) SerializePublic() ([]byte, error) {
	return k.serialize(true)
}

func (k *X25519Key) Deserialize(data []byte) (KeyBase, error) {
	versionBytes := data[:version.VersionSerialSize]
	genericVer, err := version.Deserialize(versionTypeName, versionBytes)
	if err != nil {
		return nil, err
	}
	ver := genericVer.(*X25519KeyVersion)

	result := &X25519Key{version: ver}

	buf := bytes.NewBuffer(data[version.VersionSerialSize:])
	switch ver {
	case VERSION_ONE:
		var privKeyLen int32
		err = binary.Read(buf, binary.BigEndian, &privKeyLen)
		if err != nil {
			return nil, err
		}
		if privKeyLen > 0 {
			privBytes := make([]byte, privKeyLen)
			n, err := buf.Read(privBytes)
			if err != nil {
				return nil, err
			}
			if n != len(privBytes) {
				return nil, fmt.Errorf("Read wrong number of bytes when deserializing private key")
			}
			priv, err := DeserializePriv(privBytes)
			if err != nil {
				return nil, err
			}
			result.priv = priv
		}

		var pubKeyLen int32
		err = binary.Read(buf, binary.BigEndian, &pubKeyLen)
		if err != nil {
			return nil, err
		}
		if pubKeyLen > 0 {
			pubBytes := make([]byte, pubKeyLen)
			n, err := buf.Read(pubBytes)
			if err != nil {
				return nil, err
			}
			if n != len(pubBytes) {
				return nil, fmt.Errorf("Read wrong number of bytes when deserializing public key")
			}
			pub, err := DeserializePub(pubBytes)
			if err != nil {
				return nil, err
			}
			result.pub = pub
			if result.priv != nil {
				result.priv.pub = pub
			}
		}
	default:
		return nil, fmt.Errorf("Unknown key version %v", ver.GetVersion().GetVersion())
	}
	return result, nil
}

func (k *X25519Key) CanEncrypt() bool {
	return k.priv != nil || k.pub != nil
}

func (k *X25519Key) CanDecrypt() bool {
	return k.priv != nil
}

func (k *X25519Key) Encrypt(plaintext []byte) ([]byte, error) {
	if k.pub == nil {
		pub, err := k.priv.generatePublic()
		if err != nil {
			return nil, err
		}
		k.pub = pub
	}
	return k.pub.EncryptAsym(plaintext)
}

func (k *X25519Key) Decrypt(ciphertext []byte) ([]byte, error) {
	return k.priv.DecryptAsym(ciphertext)
}

func (k *X25519Key) GetPublicKey() KeyPublic {
	return k.pub
}

func (k *X25519Key) GetPrivateKey() KeyPrivate {
	return k.priv
}
