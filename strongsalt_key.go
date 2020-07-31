package strongsaltcrypto

import (
	"bytes"
	"encoding/binary"
	"fmt"

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
	Type_Secretbox  = newKeyType("SECRETBOX", true, false, &secretbox.SecretboxKey{})
	Type_X25519     = newKeyType("X25519", false, false, &x25519.X25519Key{})
	Type_XChaCha20  = newKeyType("XCHACHA20", true, true, &xchacha20.XChaCha20Key{})
	Type_HMACSha512 = newKeyType("HMAC-SHA512", false, false, &hmac.HmacKey{HashType: hashtype.TypeSha512, KeyLen: 32})
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

// The serialization/deserialization format is as follows:
//
// Version 1:
//  ---------------------------------------------------------
// | version(4 bytes) | keyTypeLen(2 bytes) | keyType | data |
//  ---------------------------------------------------------
//
// For format of the "data" portion will depend on the key type. Each key type
// will be handled by a separate class, and the format will be defined in the
// specified class.
//

func (k *StrongSaltKey) serialize(metaOnly bool) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(k.Version.GetVersion().Serialize())

	switch k.Version {
	case VERSION_ONE:
		err := binary.Write(buf, binary.BigEndian, uint16(len(k.Type.Name)))
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
		} else {
			keyBytes, err := k.Key.Serialize()
			if err != nil {
				return nil, err
			}
			serialKey = keyBytes
		}
		buf.Write(serialKey)
	}
	return buf.Bytes(), nil
}

func (k *StrongSaltKey) SerializeMeta() ([]byte, error) {
	return k.serialize(true)
}

func (k *StrongSaltKey) Serialize() ([]byte, error) {
	return k.serialize(false)
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
		keyTypeLenBytes := make([]byte, keyTypeLenSerialSize)
		buf.Read(keyTypeLenBytes)
		keyTypeLen := binary.BigEndian.Uint16(keyTypeLenBytes)
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
		keyBytes := buf.Bytes()
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

func (k *StrongSaltKey) Decrypt(ciphertext []byte) ([]byte, error) {
	if !k.Key.CanDecrypt() {
		return nil, fmt.Errorf("This key cannot decrypt data.")
	}
	return k.Key.(KeyEncryptDecrypt).Decrypt(ciphertext)
}

func (k *StrongSaltKey) CanMAC() bool {
	_, ok := k.Key.(KeyMAC)
	return ok
}

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
