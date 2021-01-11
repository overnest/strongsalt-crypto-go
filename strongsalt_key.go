package strongsaltcrypto

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/overnest/strongsalt-crypto-go/aesgcm"

	"github.com/overnest/strongsalt-crypto-go/hashtype"
	"github.com/overnest/strongsalt-crypto-go/hmac"
	. "github.com/overnest/strongsalt-crypto-go/interfaces"
	"github.com/overnest/strongsalt-crypto-go/secretbox"
	"github.com/overnest/strongsalt-crypto-go/version"
	"github.com/overnest/strongsalt-crypto-go/x25519"
	"github.com/overnest/strongsalt-crypto-go/xchacha20"
)

/*
** TYPES
 */

const (
	keyTypeLenSerialSize   = 2
	generateKeyFuncName    = "GenerateKey"
	deserializeKeyFuncName = "Deserialize"
)

var (
	/*Type_X25519    = newKeyType("X25519", false, false, reflect.TypeOf(x25519.X25519Key{}))
	Type_XChaCha20 = newKeyType("XChaCha20", true, true, reflect.TypeOf(xchacha20.XChaCha20Key{}))*/
	Type_Secretbox     = newKeyType("SECRETBOX", true, false, &secretbox.SecretboxKey{})
	Type_X25519        = newKeyType("X25519", false, false, &x25519.X25519Key{})
	Type_XChaCha20     = newKeyType("XCHACHA20", true, true, &xchacha20.XChaCha20Key{})
	Type_XChaCha20HMAC = newKeyType("XCHACHA20HMAC", true, true, &xchacha20.XChaCha20Key{Mac: true})
	Type_HMACSha512    = newKeyType("HMACSHA512", false, false, &hmac.HmacKey{HashType: hashtype.TypeSha512, KeyLen: 32})
	Type_AesGcm        = newKeyType("AESGCM", true, false, &aesgcm.AesGcmKey{})
)

type KeyType struct {
	Name      string
	Symmetric bool
	Midstream bool
	//Type      reflect.Type
	Type KeySerialization
}

var typeMap map[string]*KeyType = make(map[string]*KeyType)

//func newKeyType(name string, symmetric, midstream bool, rType reflect.Type) *KeyType {
func newKeyType(name string, symmetric, midstream bool, rType KeySerialization) *KeyType {
	keyType := &KeyType{name, symmetric, midstream, rType}
	typeMap[name] = keyType
	return keyType
}

func deserializeKeyType(data []byte) (*KeyType, error) {
	keyTypeName := string(data)
	keyType, exists := typeMap[keyTypeName]
	if !exists {
		return nil, fmt.Errorf("Cannot find key type: %v.", keyTypeName)
	}
	return keyType, nil
}

func TypeFromName(name string) *KeyType {
	return typeMap[name]
}

/*
** VERSIONS
 */

const (
	versionTypeName = "KeyVersion"
)

var (
	VERSION_ONE = newKeyVersion("ONE", 1)
	curVersion  = VERSION_ONE
)

type KeyVersion struct {
	Name    string
	Version version.Version
}

func (kv *KeyVersion) GetVersion() version.Version {
	return kv.Version
}

var keyVersionMap map[int32]version.VersionInterface = make(map[int32]version.VersionInterface)

func newKeyVersion(name string, ver int32) *KeyVersion {
	keyVersion := &KeyVersion{name, version.Version(ver)}
	keyVersionMap[ver] = keyVersion
	return keyVersion
}

/*
** INITIALIZATION
 */

func init() {
	//version.SetClassVersions(reflect.TypeOf(KeyVersion{}).Name(), keyVersionMap)
	version.SetClassVersions(versionTypeName, keyVersionMap)
}

/*
** MAIN
 */

type StrongSaltKey struct {
	Type    *KeyType
	Version *KeyVersion
	Key     KeyBase
}

func NewSymmetric(keyType *KeyType) (*StrongSaltKey, error) {
	symmType, ok := keyType.Type.(KeySymmetric)
	if !ok {
		return nil, fmt.Errorf("Type %v does not implement KeySymmetric interface", keyType.Name)
	}
	key := symmType.New()

	return &StrongSaltKey{
		Version: curVersion,
		Type:    keyType,
		Key:     key,
	}, nil
}

func GenerateKey(keyType *KeyType) (*StrongSaltKey, error) {
	/*generateKey, exists := keyType.Type.MethodByName(generateKeyFuncName)
	if !exists {
		return nil, fmt.Errorf("Cannot find method %v for type %v", generateKeyFuncName, keyType.Name)
	}
	returnValues := generateKey.Func.Call(nil)
	err := returnValues[1].Interface().(error)
	if err != nil {
		return nil, err
	}
	key := returnValues[0].Interface().(KeyBase)*/
	key, err := keyType.Type.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &StrongSaltKey{keyType, curVersion, key}, nil
}

func (k *StrongSaltKey) IsSymmetric() bool {
	_, ok := k.Key.(KeySymmetric)
	return ok
}

func (k *StrongSaltKey) IsMidstream() bool {
	_, ok := k.Key.(KeyMidstream)
	return ok
}

func (k *StrongSaltKey) IsAsymmetric() bool {
	_, ok := k.Key.(KeyAsymmetric)
	return ok
}

func (k *StrongSaltKey) CanEncrypt() bool {
	return k.Key.CanEncrypt()
}

func (k *StrongSaltKey) CanDecrypt() bool {
	return k.Key.CanDecrypt()
}

func (k *StrongSaltKey) CanMAC() bool {
	mac, ok := k.Key.(KeyMAC)
	return ok && mac.CanMAC()
}

// The serialization/deserialization format is as follows:
//
// Version 1:
//  ----------------------------------------------------------------------------
// | version(4 bytes) | keyTypeLen(4 bytes) | keyType | dataLen(4 bytes) | data |
//  ----------------------------------------------------------------------------
//
// For format of the "data" portion will depend on the key type. Each key type
// will be handled by a separate class, and the format will be defined in the
// specified class.
//

func (k *StrongSaltKey) serialize(metaOnly bool, publicOnly bool) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(k.Version.GetVersion().Serialize())

	switch k.Version {
	case VERSION_ONE:
		err := binary.Write(buf, binary.BigEndian, int32(len(k.Type.Name)))
		if err != nil {
			return nil, err
		}
		buf.WriteString(k.Type.Name)

		var serialKey []byte
		if metaOnly {
			key, ok := k.Key.(KeySymmetric)
			if !ok {
				return nil, fmt.Errorf("Key does not implement KeySymmetric interface")
			}
			keyBytes, err := key.SerializeMeta()
			if err != nil {
				return nil, err
			}
			serialKey = keyBytes
		} else if publicOnly {
			key, ok := k.Key.(KeyAsymmetric)
			if !ok {
				return nil, fmt.Errorf("Key does not implement KeyAsymmetric interface")
			}
			keyBytes, err := key.SerializePublic()
			if err != nil {
				return nil, err
			}
			serialKey = keyBytes
		} else {
			keyBytes, err := k.Key.Serialize()
			if err != nil {
				return nil, err
			}
			serialKey = keyBytes
		}
		err = binary.Write(buf, binary.BigEndian, int32(len(serialKey)))
		if err != nil {
			return nil, err
		}
		buf.Write(serialKey)
	}
	return buf.Bytes(), nil
}

func (k *StrongSaltKey) SerializeMeta() ([]byte, error) {
	return k.serialize(true, false)
}

func (k *StrongSaltKey) SerializePublic() ([]byte, error) {
	return k.serialize(false, true)
}

func (k *StrongSaltKey) Serialize() ([]byte, error) {
	return k.serialize(false, false)
}

func DeserializeKey(data []byte) (*StrongSaltKey, error) {
	if len(data) < version.VersionSerialSize+keyTypeLenSerialSize+2 {
		return nil, fmt.Errorf("data doesn't contain enough bytes to deserialize")
	}
	buf := bytes.NewBuffer(data)
	versionBytes := make([]byte, version.VersionSerialSize)
	buf.Read(versionBytes)
	genericVer, err := version.Deserialize(versionTypeName, versionBytes)
	if err != nil {
		return nil, err
	}
	ver := genericVer.(*KeyVersion)
	var keyType *KeyType
	var key KeyBase
	switch ver {
	case VERSION_ONE:
		var keyTypeLen int32
		err := binary.Read(buf, binary.BigEndian, &keyTypeLen)
		if err != nil {
			return nil, err
		}
		keyTypeBytes := make([]byte, keyTypeLen)
		n, err := buf.Read(keyTypeBytes)
		if err != nil {
			return nil, err
		}
		if n != int(keyTypeLen) {
			return nil, fmt.Errorf("read wrong number of bytes when deserializing key type")
		}
		keyType, err = deserializeKeyType(keyTypeBytes)
		if err != nil {
			return nil, err
		}
		var keyDataLen int32
		err = binary.Read(buf, binary.BigEndian, &keyDataLen)
		if err != nil {
			return nil, err
		}
		keyBytes := make([]byte, keyDataLen)
		n, err = buf.Read(keyBytes)
		if err != nil {
			return nil, err
		}
		if n != int(keyDataLen) {
			return nil, fmt.Errorf("read wrong number of bytes when deserializing key data")
		}
		/*deserializeKeyFunc, exists := keyType.Type.MethodByName(deserializeKeyFuncName)
		if !exists {
			return nil, fmt.Errorf("key type %v does not have method %v", keyType.Name, deserializeKeyFuncName)
		}
		returnValues := deserializeKeyFunc.Func.Call([]reflect.Value{nil, keyBytes})*/
		key, err = keyType.Type.Deserialize(keyBytes)
		if err != nil {
			return nil, err
		}
	}
	return &StrongSaltKey{
		Version: ver,
		Type:    keyType,
		Key:     key,
	}, nil
}

func (k *StrongSaltKey) Encrypt(plaintext []byte) ([]byte, error) {
	if !k.Key.CanEncrypt() {
		return nil, fmt.Errorf("This key cannot encrypt data.")
	}
	return k.Key.(KeyEncryptDecrypt).Encrypt(plaintext)
}

func (k *StrongSaltKey) EncryptBase64(plaintext []byte) (string, error) {
	ciphertext, err := k.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func (k *StrongSaltKey) Decrypt(ciphertext []byte) ([]byte, error) {
	if !k.Key.CanDecrypt() {
		return nil, fmt.Errorf("This key cannot decrypt data.")
	}
	return k.Key.(KeyEncryptDecrypt).Decrypt(ciphertext)
}

func (k *StrongSaltKey) DecryptBase64(ciphertext string) ([]byte, error) {
	cipherbytes, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	return k.Decrypt(cipherbytes)
}

//
// MIDSTREAM
//

func (k *StrongSaltKey) EncryptStream() (*Encryptor, error) {
	key, ok := k.Key.(KeyMidstream)
	if !ok {
		return nil, fmt.Errorf("Cannot stream. Key does not implement KeyMidstream interface.")
	}
	return NewEncryptor(key)
}

func (k *StrongSaltKey) DecryptStream(initialCount int32) (*Decryptor, error) {
	key, ok := k.Key.(KeyMidstream)
	if !ok {
		return nil, fmt.Errorf("Cannot stream. Key does not implement KeyMidstream interface.")
	}
	return NewDecryptor(key, initialCount)
}

func (k *StrongSaltKey) EncryptIC(plaintext []byte, nonce []byte, count int32) ([]byte, error) {
	if !k.Key.CanEncrypt() {
		return nil, fmt.Errorf("This key cannot encrypt data.")
	}
	key, ok := k.Key.(KeyMidstream)
	if !ok {
		return nil, fmt.Errorf("This key cannot encrypt midstream")
	}
	return key.EncryptIC(plaintext, nonce, count)
}

func (k *StrongSaltKey) DecryptIC(ciphertext []byte, nonce []byte, count int32) ([]byte, error) {
	if !k.Key.CanDecrypt() {
		return nil, fmt.Errorf("This key cannot decrypt data.")
	}
	key, ok := k.Key.(KeyMidstream)
	if !ok {
		return nil, fmt.Errorf("This key cannot decrypt midstream")
	}
	return key.DecryptIC(ciphertext, nonce, count)
}

func (k *StrongSaltKey) BlockSize() int {
	key, ok := k.Key.(KeyMidstream)
	if !ok {
		return 0
	}
	return key.BlockSize()
}

func (k *StrongSaltKey) NonceSize() int {
	key, ok := k.Key.(KeyMidstream)
	if !ok {
		return 0
	}
	return key.NonceSize()
}

//
// MAC
//

func (k *StrongSaltKey) MACWrite(data []byte) (int, error) {
	mac, ok := k.Key.(KeyMAC)
	if !ok {
		return 0, fmt.Errorf("Key of type %v is not a MAC key", k.Type.Name)
	}
	return mac.Write(data)
}

func (k *StrongSaltKey) MACSum(data []byte) ([]byte, error) {
	mac, ok := k.Key.(KeyMAC)
	if !ok {
		return nil, fmt.Errorf("Key of type %v is not a MAC key", k.Type.Name)
	}
	return mac.Sum(data)
}

func (k *StrongSaltKey) MACVerify(tag []byte) (bool, error) {
	mac, ok := k.Key.(KeyMAC)
	if !ok {
		return false, fmt.Errorf("Key of type %v is not a MAC key", k.Type.Name)
	}
	return mac.Verify(tag)
}

func (k *StrongSaltKey) MACReset() error {
	mac, ok := k.Key.(KeyMAC)
	if !ok {
		return fmt.Errorf("Key of type %v is not a MAC key", k.Type.Name)
	}
	mac.Reset()
	return nil
}

func (k *StrongSaltKey) GetRawKey() ([]byte, error) {
	key, ok := k.Key.(KeySymmetric)
	if !ok {
		return nil, fmt.Errorf("Key does not implement KeySymmetric interface")
	}
	return key.GetKey(), nil
}
