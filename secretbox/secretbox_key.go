package secretbox

import (
	"bytes"
	"crypto/rand"
	"fmt"

	. "github.com/overnest/strongsalt-crypto-go/interfaces"
	"github.com/overnest/strongsalt-crypto-go/version"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keySizeV1       = 32
	nonceSizeV1     = 24
	versionTypeName = "SecretboxKeyVersion"
)

var (
	VERSION_ONE = newSecretboxKeyVersion("ONE", 1)
	curVersion  = VERSION_ONE
)

type SecretboxKeyVersion struct {
	Name    string
	Version version.Version
}

func (kv *SecretboxKeyVersion) GetVersion() version.Version {
	return kv.Version
}

var keyVersionMap map[int32]version.VersionInterface = make(map[int32]version.VersionInterface)

func newSecretboxKeyVersion(name string, ver int32) *SecretboxKeyVersion {
	keyVersion := &SecretboxKeyVersion{name, version.Version(ver)}
	keyVersionMap[ver] = keyVersion
	return keyVersion
}

func init() {
	version.SetClassVersions(versionTypeName, keyVersionMap)
}

type SecretboxKey struct {
	version *SecretboxKeyVersion
	key     *[keySizeV1]byte
}

func (k *SecretboxKey) GenerateKey() (KeyBase, error) {
	keySlice := make([]byte, keySizeV1)
	n, err := rand.Read(keySlice)
	if err != nil {
		return nil, err
	}
	if n != len(keySlice) {
		return nil, fmt.Errorf("xchacha20 key received wrong number of random bytes")
	}
	var key [keySizeV1]byte
	for i := 0; i < len(key); i++ {
		key[i] = keySlice[i]
	}
	return &SecretboxKey{key: &key, version: curVersion}, nil
}

//
// The serialization/deserialization format is as follows:
//
// Version 1:
//  -------------------------
// | version(4 bytes) | key |
//  -------------------------
//

func (k *SecretboxKey) Deserialize(data []byte) (KeyBase, error) {
	versionBytes := data[:version.VersionSerialSize]
	genericVer, err := version.Deserialize(versionTypeName, versionBytes)
	if err != nil {
		return nil, err
	}
	ver := genericVer.(*SecretboxKeyVersion)
	buf := bytes.NewBuffer(data[version.VersionSerialSize:])
	switch ver {
	case VERSION_ONE:
		/*var keyLen uint16
		err = binary.Read(buf, binary.LittleEndian, &keyLen)
		if err != nil {
			return nil, err
		}*/
		keySlice := make([]byte, keySizeV1)
		n, err := buf.Read(keySlice)
		if err != nil {
			return nil, err
		}
		if n != len(keySlice) {
			return nil, fmt.Errorf("Read wrong number of bytes when deserializing key")
		}
		var key [keySizeV1]byte
		for i := 0; i < len(key); i++ {
			key[i] = keySlice[i]
		}
		return &SecretboxKey{key: &key, version: ver}, nil
	default:
		return nil, fmt.Errorf("Unknown key version %v", ver.GetVersion().GetVersion())
	}
}

func (k *SecretboxKey) Serialize() ([]byte, error) {
	ver := version.Serialize(k.version)
	key := k.GetKey()

	return append(ver, key...), nil
}

func (k *SecretboxKey) CanEncrypt() bool {
	return true
}

func (k *SecretboxKey) CanDecrypt() bool {
	return true
}

func (k *SecretboxKey) CanMAC() bool {
	return false
}

func (k *SecretboxKey) Encrypt(plaintext []byte) ([]byte, error) {
	nonceSlice := make([]byte, nonceSizeV1)
	n, _ := rand.Read(nonceSlice)
	if n != len(nonceSlice) {
		return nil, fmt.Errorf("Generate nonce returned wrong number of bytes")
	}
	var nonce [nonceSizeV1]byte
	for i := 0; i < len(nonce); i++ {
		nonce[i] = nonceSlice[i]
	}
	ciphertext := secretbox.Seal(nil, plaintext, &nonce, k.key)

	return append(nonceSlice, ciphertext...), nil
}

func (k *SecretboxKey) Decrypt(ciphertext []byte) ([]byte, error) {
	var nonce [nonceSizeV1]byte
	for i := 0; i < len(nonce); i++ {
		nonce[i] = ciphertext[i]
	}
	ciphertext = ciphertext[nonceSizeV1:]

	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, k.key)
	if !ok {
		return nil, fmt.Errorf("Secretbox open returned false")
	}

	return plaintext, nil
}

func (k *SecretboxKey) GetKey() []byte {
	return k.key[:]
}
