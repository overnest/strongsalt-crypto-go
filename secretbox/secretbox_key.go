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

func (_ *SecretboxKey) New() KeySymmetric {
	return &SecretboxKey{
		version: curVersion,
	}
}

func (k *SecretboxKey) SetKey(data []byte) error {
	var key [keySizeV1]byte
	for i := 0; i < len(key); i++ {
		key[i] = data[i]
	}
	k.key = &key
	return nil
}

func (_ *SecretboxKey) GenerateKey() (KeyBase, error) {
	keySlice := make([]byte, keySizeV1)
	n, err := rand.Read(keySlice)
	if err != nil {
		return nil, err
	}
	if n != len(keySlice) {
		return nil, fmt.Errorf("xchacha20 key received wrong number of random bytes")
	}
	result := &SecretboxKey{version: curVersion}
	result.SetKey(keySlice)

	return result, nil
}

//
// The serialization/deserialization format is as follows:
//
// Version 1:
//  -------------------------
// | version(4 bytes) | key |
//  -------------------------
//

func (_ *SecretboxKey) Deserialize(data []byte) (KeyBase, error) {
	if len(data) < version.VersionSerialSize {
		return nil, fmt.Errorf("Cannot deserialize version. Not enough bytes.")
	}
	versionBytes := data[:version.VersionSerialSize]
	genericVer, err := version.Deserialize(versionTypeName, versionBytes)
	if err != nil {
		return nil, err
	}
	ver := genericVer.(*SecretboxKeyVersion)
	buf := bytes.NewBuffer(data[version.VersionSerialSize:])
	switch ver {
	case VERSION_ONE:
		result := &SecretboxKey{version: ver}
		if buf.Len() > 0 {
			keySlice := make([]byte, keySizeV1)
			n, err := buf.Read(keySlice)
			if err != nil {
				return nil, err
			}
			if n != len(keySlice) {
				return nil, fmt.Errorf("Read wrong number of bytes when deserializing key")
			}
			result.SetKey(keySlice)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("Unknown key version %v", ver.GetVersion().GetVersion())
	}
}

func (k *SecretboxKey) SerializeMeta() ([]byte, error) {
	return version.Serialize(k.version), nil
}

func (k *SecretboxKey) Serialize() ([]byte, error) {
	meta, err := k.SerializeMeta()
	if err != nil {
		return nil, err
	}
	switch k.version {
	case VERSION_ONE:
		key := k.GetKey()
		return append(meta, key...), nil
	}

	return nil, fmt.Errorf("Cannot serialize key with invalid version")
}

func (k *SecretboxKey) CanEncrypt() bool {
	return k.key != nil
}

func (k *SecretboxKey) CanDecrypt() bool {
	return k.key != nil
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
	if len(ciphertext) < k.getNonceSize() {
		return nil, fmt.Errorf("Ciphertext isn't long enough to contain nonce")
	}
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

func (k *SecretboxKey) getNonceSize() int {
	if k.version == VERSION_ONE {
		return nonceSizeV1
	}
	return nonceSizeV1
}

func (k *SecretboxKey) GetKey() []byte {
	if k.key == nil {
		return nil
	} else {
		return k.key[:]
	}
}

func (k *SecretboxKey) KeyLen() int {
	switch k.version {
	case VERSION_ONE:
		return keySizeV1
	}
	return 0
}
