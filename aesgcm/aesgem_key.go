package aesgcm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	. "github.com/overnest/strongsalt-crypto-go/interfaces"
	"github.com/overnest/strongsalt-crypto-go/version"
)

const (
	versionTypeName = "AesGcmKeyVersion"
)

var (
	VERSION_ONE = newAesGcmKeyVersion("ONE", 1)
	curVersion  = VERSION_ONE
	keySize     = 32
	NonceSize   = 12
)

type AesGcmKeyVersion struct {
	Name    string
	Version version.Version
}

func (kv *AesGcmKeyVersion) GetVersion() version.Version {
	return kv.Version
}

var keyVersionMap = make(map[int32]version.VersionInterface)

func newAesGcmKeyVersion(name string, ver int32) *AesGcmKeyVersion {
	keyVersion := &AesGcmKeyVersion{name, version.Version(ver)}
	keyVersionMap[ver] = keyVersion
	return keyVersion
}

func init() {
	version.SetClassVersions(versionTypeName, keyVersionMap)
}

type AesGcmKey struct {
	version *AesGcmKeyVersion
	key     []byte
	keyLen  int
}

func (k *AesGcmKey) New() KeySymmetric {
	return &AesGcmKey{
		version: curVersion,
		keyLen:  keySize,
	}
}

func (k *AesGcmKey) GenerateKey() (KeyBase, error) {
	key := make([]byte, keySize)
	n, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	if n != len(key) {
		return nil, fmt.Errorf("aesgcm key received wrong number of random bytes")
	}
	result := &AesGcmKey{
		version: curVersion,
		keyLen:  keySize,
	}
	result.SetKey(key)
	return result, nil
}

//
// The serialization/deserialization format is as follows:
//
// Version 1:
//  ------------------------------------------
// | version(4 bytes) | keyLen(4 bytes) | key |
//  ------------------------------------------
//
func (k *AesGcmKey) Serialize() ([]byte, error) {
	meta, err := k.SerializeMeta()
	if err != nil {
		return nil, err
	}
	switch k.version {
	case VERSION_ONE:
		return append(meta, k.GetKey()...), nil
	}
	return nil, fmt.Errorf("Cannot serialize key with invalid version")
}

func (k *AesGcmKey) SerializeMeta() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(version.Serialize(k.version))
	switch k.version {
	case VERSION_ONE:
		binary.Write(buf, binary.BigEndian, int32(len(k.GetKey())))
	}
	return buf.Bytes(), nil
}

func (k *AesGcmKey) Deserialize(data []byte) (KeyBase, error) {
	versionBytes := data[:version.VersionSerialSize]
	genericVer, err := version.Deserialize(versionTypeName, versionBytes)
	if err != nil {
		return nil, err
	}
	ver := genericVer.(*AesGcmKeyVersion)
	result := &AesGcmKey{version: ver}

	buf := bytes.NewBuffer(data[version.VersionSerialSize:])

	switch ver {
	case VERSION_ONE:
		var keyLen int32
		err = binary.Read(buf, binary.BigEndian, &keyLen)
		if err != nil {
			return nil, err
		}
		result.keyLen = int(keyLen)
		if buf.Len() > 0 {
			if buf.Len() != int(keyLen) {
				return nil, fmt.Errorf("Key length is %v but have %v bytes.", keyLen, buf.Len())
			}
			key := make([]byte, keyLen)
			n, err := buf.Read(key)
			if err != nil {
				return nil, err
			}
			if n != len(key) {
				return nil, fmt.Errorf("Read wrong number of bytes when deserializing key")
			}
			result.SetKey(key)
		}
	default:
		return nil, fmt.Errorf("Unknown key version %v", ver.GetVersion().GetVersion())
	}
	return result, nil
}

func (k *AesGcmKey) CanEncrypt() bool {
	return k.key != nil && len(k.key) == k.KeyLen()
}

func (k *AesGcmKey) CanDecrypt() bool {
	return k.key != nil && len(k.key) == k.KeyLen()
}

func (k *AesGcmKey) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	n, _ := rand.Read(nonce)
	if n != len(nonce) {
		return nil, fmt.Errorf("Generate nonce returned wrong number of bytes")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func (k *AesGcmKey) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize {
		return nil, fmt.Errorf("First bytes of ciphertext must contain nonce.")
	}
	nonce := ciphertext[:NonceSize]
	ciphertext = ciphertext[NonceSize:]

	block, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (k *AesGcmKey) SetKey(bytes []byte) error {
	k.key = bytes
	return nil
}

func (k *AesGcmKey) KeyLen() int {
	return k.keyLen
}

func (k *AesGcmKey) GetKey() []byte {
	return k.key
}
