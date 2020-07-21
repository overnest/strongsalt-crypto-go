package xchacha20

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	. "github.com/overnest/strongsalt-crypto-go/interfaces"
	"github.com/overnest/strongsalt-crypto-go/utils"
	"github.com/overnest/strongsalt-crypto-go/version"
	"golang.org/x/crypto/chacha20"
)

const (
	versionTypeName = "XChaCha20KeyVersion"
)

var (
	VERSION_ONE = newXChaCha20KeyVersion("ONE", 1)
	curVersion  = VERSION_ONE
)

type XChaCha20KeyVersion struct {
	Name    string
	Version version.Version
}

func (kv *XChaCha20KeyVersion) GetVersion() version.Version {
	return kv.Version
}

var keyVersionMap map[int32]version.VersionInterface = make(map[int32]version.VersionInterface)

func newXChaCha20KeyVersion(name string, ver int32) *XChaCha20KeyVersion {
	keyVersion := &XChaCha20KeyVersion{name, version.Version(ver)}
	keyVersionMap[ver] = keyVersion
	return keyVersion
}

func init() {
	version.SetClassVersions(versionTypeName, keyVersionMap)
}

type XChaCha20Key struct {
	version *XChaCha20KeyVersion
	key     []byte
}

func (k *XChaCha20Key) GenerateKey() (KeyBase, error) {
	key := make([]byte, chacha20.KeySize)
	n, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	if n != len(key) {
		return nil, fmt.Errorf("xchacha20 key received wrong number of random bytes")
	}
	return &XChaCha20Key{key: key, version: curVersion}, nil
}

//
// The serialization/deserialization format is as follows:
//
// Version 1:
//  ------------------------------------------
// | version(4 bytes) | keyLen(4 bytes) | key |
//  ------------------------------------------
//

func (k *XChaCha20Key) Deserialize(data []byte) (KeyBase, error) {
	versionBytes := data[:version.VersionSerialSize]
	genericVer, err := version.Deserialize(versionTypeName, versionBytes)
	if err != nil {
		return nil, err
	}
	ver := genericVer.(*XChaCha20KeyVersion)
	var key []byte
	buf := bytes.NewBuffer(data[version.VersionSerialSize:])
	switch ver {
	case VERSION_ONE:
		var keyLen uint32
		err = binary.Read(buf, binary.LittleEndian, &keyLen)
		if err != nil {
			return nil, err
		}
		key = make([]byte, keyLen)
		n, err := buf.Read(key)
		if err != nil {
			return nil, err
		}
		if n != len(key) {
			return nil, fmt.Errorf("Read wrong number of bytes when deserializing key")
		}
	default:
		return nil, fmt.Errorf("Unknown key version %v", ver.GetVersion().GetVersion())
	}
	return &XChaCha20Key{key: key, version: ver}, nil
}

func (k *XChaCha20Key) Serialize() ([]byte, error) {
	return utils.KeySymmetricSerialize(k.GetKey(), version.Serialize(k.version))
}

func (k *XChaCha20Key) CanEncrypt() bool {
	return true
}

func (k *XChaCha20Key) CanDecrypt() bool {
	return true
}

func (k *XChaCha20Key) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, chacha20.NonceSizeX)
	n, _ := rand.Read(nonce)
	if n != len(nonce) {
		return nil, fmt.Errorf("Generate nonce returned wrong number of bytes")
	}

	cipher, err := chacha20.NewUnauthenticatedCipher(k.GetKey(), nonce)
	if err != nil {
		return nil, fmt.Errorf("XChaCha20 New cipher error: %v", err)
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)

	return append(nonce, ciphertext...), nil
}

func (k *XChaCha20Key) Decrypt(ciphertext []byte) ([]byte, error) {
	nonce := ciphertext[:chacha20.NonceSizeX]
	ciphertext = ciphertext[chacha20.NonceSizeX:]

	cipher, err := chacha20.NewUnauthenticatedCipher(k.GetKey(), nonce)
	if err != nil {
		return nil, fmt.Errorf("XChaCha20 new cipher error: %v", err)
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func (k *XChaCha20Key) GetKey() []byte {
	return k.key
}
