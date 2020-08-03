package xchacha20

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	. "github.com/overnest/strongsalt-crypto-go/interfaces"
	"github.com/overnest/strongsalt-crypto-go/version"
	"golang.org/x/crypto/chacha20"
)

const (
	versionTypeName = "XChaCha20KeyVersion"
	blockSizeV1     = 64
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
	keyLen  int
}

func (k *XChaCha20Key) New() KeySymmetric {
	return &XChaCha20Key{
		version: curVersion,
		keyLen:  chacha20.KeySize,
	}
}

func (k *XChaCha20Key) SetKey(data []byte) error {
	k.key = data
	k.keyLen = len(data)
	return nil
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
	result := &XChaCha20Key{version: curVersion}
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

func (k *XChaCha20Key) Deserialize(data []byte) (KeyBase, error) {
	versionBytes := data[:version.VersionSerialSize]
	genericVer, err := version.Deserialize(versionTypeName, versionBytes)
	if err != nil {
		return nil, err
	}
	ver := genericVer.(*XChaCha20KeyVersion)
	result := &XChaCha20Key{version: ver}

	buf := bytes.NewBuffer(data[version.VersionSerialSize:])

	switch ver {
	case VERSION_ONE:
		var keyLen uint32
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

func (k *XChaCha20Key) SerializeMeta() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(version.Serialize(k.version))
	switch k.version {
	case VERSION_ONE:
		binary.Write(buf, binary.BigEndian, int32(len(k.GetKey())))
	}
	return buf.Bytes(), nil
}

func (k *XChaCha20Key) Serialize() ([]byte, error) {
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

func (k *XChaCha20Key) CanEncrypt() bool {
	return k.key != nil && len(k.key) == k.KeyLen()
}

func (k *XChaCha20Key) CanDecrypt() bool {
	return k.key != nil && len(k.key) == k.KeyLen()
}

func (k *XChaCha20Key) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, chacha20.NonceSizeX)
	n, _ := rand.Read(nonce)
	if n != len(nonce) {
		return nil, fmt.Errorf("Generate nonce returned wrong number of bytes")
	}

	ciphertext, err := k.EncryptIC(plaintext, nonce, 0)
	if err != nil {
		return nil, err
	}

	return append(nonce, ciphertext...), nil
}

func (k *XChaCha20Key) EncryptIC(plaintext []byte, nonce []byte, count uint32) ([]byte, error) {
	cipher, err := chacha20.NewUnauthenticatedCipher(k.GetKey(), nonce)
	if err != nil {
		return nil, fmt.Errorf("XChaCha20 New cipher error: %v", err)
	}
	cipher.SetCounter(count)

	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil
}

func (k *XChaCha20Key) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < chacha20.NonceSizeX {
		return nil, fmt.Errorf("First bytes of ciphertext must contain nonce.")
	}
	nonce := ciphertext[:chacha20.NonceSizeX]
	ciphertext = ciphertext[chacha20.NonceSizeX:]

	return k.DecryptIC(ciphertext, nonce, 0)
}

func (k *XChaCha20Key) DecryptIC(ciphertext []byte, nonce []byte, count uint32) ([]byte, error) {
	cipher, err := chacha20.NewUnauthenticatedCipher(k.GetKey(), nonce)
	if err != nil {
		return nil, fmt.Errorf("XChaCha20 new cipher error: %v", err)
	}
	cipher.SetCounter(count)

	plaintext := make([]byte, len(ciphertext))
	cipher.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func (k *XChaCha20Key) GetKey() []byte {
	return k.key
}

func (k *XChaCha20Key) KeyLen() int {
	return k.keyLen
}

func (k *XChaCha20Key) BlockSize() int {
	switch k.version {
	case VERSION_ONE:
		return blockSizeV1
	}
	return blockSizeV1
}

func (k *XChaCha20Key) NonceSize() int {
	switch k.version {
	case VERSION_ONE:
		return chacha20.NonceSizeX
	}
	return chacha20.NonceSizeX
}
