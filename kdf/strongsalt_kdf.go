package kdf

import (
	"bytes"
	"encoding/binary"
	"fmt"

	ssc "github.com/overnest/strongsalt-crypto-go"
	. "github.com/overnest/strongsalt-crypto-go/interfaces"
	"github.com/overnest/strongsalt-crypto-go/kdf/pbkdf2"
	"github.com/overnest/strongsalt-crypto-go/version"
)

/*
** TYPES
 */

const (
	kdfTypeLenSerialSize   = 2
	generateKeyFuncName    = "GenerateKey"
	deserializeKdfFuncName = "Deserialize"
)

var (
	Type_Pbkdf2 = newKdfType("PBKDF2", &pbkdf2.Pbkdf2{})
)

type KdfType struct {
	Name string
	Type KdfBase
}

var typeMap map[string]*KdfType = make(map[string]*KdfType)

func newKdfType(name string, rType KdfBase) *KdfType {
	kdfType := &KdfType{name, rType}
	typeMap[name] = kdfType
	return kdfType
}

func deserializeKdfType(data []byte) (*KdfType, error) {
	kdfTypeName := string(data)
	kdfType, exists := typeMap[kdfTypeName]
	if !exists {
		return nil, fmt.Errorf("Cannot find KDF type: %v.", kdfTypeName)
	}
	return kdfType, nil
}

func TypeFromName(name string) *KdfType {
	return typeMap[name]
}

/*
** VERSIONS
 */

const (
	versionTypeName = "KdfVersion"
)

var (
	VERSION_ONE = newKdfVersion("ONE", 1)
	curVersion  = VERSION_ONE
)

type KdfVersion struct {
	Name    string
	Version version.Version
}

func (kv *KdfVersion) GetVersion() version.Version {
	return kv.Version
}

var kdfVersionMap map[int32]version.VersionInterface = make(map[int32]version.VersionInterface)

func newKdfVersion(name string, ver int32) *KdfVersion {
	kdfVersion := &KdfVersion{name, version.Version(ver)}
	kdfVersionMap[ver] = kdfVersion
	return kdfVersion
}

/*
** INITIALIZATION
 */

func init() {
	version.SetClassVersions(versionTypeName, kdfVersionMap)
}

/*
** MAIN
 */

type StrongSaltKdf struct {
	Type    *KdfType
	Key     *ssc.StrongSaltKey
	Version *KdfVersion
	Kdf     KdfBase
}

func New(kdfType *KdfType, keyType *ssc.KeyType) (*StrongSaltKdf, error) {
	key, err := ssc.NewSymmetric(keyType)
	if err != nil {
		return nil, err
	}

	kdf, err := kdfType.Type.New()
	if err != nil {
		return nil, err
	}

	return &StrongSaltKdf{
		Version: curVersion,
		Type:    kdfType,
		Key:     key,
		Kdf:     kdf,
	}, nil
}

// The serialization/deserialization format is as follows:
//
// Version 1:
//  ------------------------------------------------------------------------------------------------------------------
// | version(4 bytes) | kdfTypeLen(4 bytes) | kdfType | kdfDataLen(4 bytes) | kdfData | keyDataLen(4 bytes) | keyData |
//  ------------------------------------------------------------------------------------------------------------------
//
// For format of the "kdfData" portion will depend on the kdf type. Each kdf type
// will be handled by a separate class, and the format will be defined in the
// specified class.
//

func (k *StrongSaltKdf) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	ver := k.Version.GetVersion().Serialize()
	n, err := buf.Write(ver)
	if err != nil {
		return nil, err
	}
	if n != len(ver) {
		return nil, fmt.Errorf("Wrong number of bytes written while serializing version")
	}

	switch k.Version {
	case VERSION_ONE:
		err = binary.Write(buf, binary.BigEndian, int32(len(k.Type.Name)))
		if err != nil {
			return nil, err
		}
		n, err = buf.WriteString(k.Type.Name)
		if err != nil {
			return nil, err
		}
		if n != len(k.Type.Name) {
			return nil, fmt.Errorf("Wrong number of bytes written while serializing kdf type name")
		}

		kdfData, err := k.Kdf.Serialize()
		if err != nil {
			return nil, err
		}
		err = binary.Write(buf, binary.BigEndian, int32(len(kdfData)))
		if err != nil {
			return nil, err
		}
		n, err = buf.Write(kdfData)
		if err != nil {
			return nil, err
		}
		if n != len(kdfData) {
			return nil, fmt.Errorf("Wrong number of bytes written while serializing kdf data")
		}

		serializedKey, err := k.Key.SerializeMeta()
		if err != nil {
			return nil, err
		}
		err = binary.Write(buf, binary.BigEndian, int32(len(serializedKey)))
		if err != nil {
			return nil, err
		}
		n, err = buf.Write(serializedKey)
		if err != nil {
			return nil, err
		}
		if n != len(serializedKey) {
			return nil, fmt.Errorf("Wrong number of bytes written while serializing key")
		}
	}

	return buf.Bytes(), nil
}

func DeserializeKdf(data []byte) (*StrongSaltKdf, error) {
	if len(data) < version.VersionSerialSize {
		return nil, fmt.Errorf("data doesn't contain enough bytes to deserialize version")
	}
	buf := bytes.NewBuffer(data)
	versionBytes := make([]byte, version.VersionSerialSize)
	buf.Read(versionBytes)
	genericVer, err := version.Deserialize(versionTypeName, versionBytes)
	if err != nil {
		return nil, err
	}
	ver := genericVer.(*KdfVersion)
	result := &StrongSaltKdf{Version: ver}

	switch ver {
	case VERSION_ONE:
		var kdfTypeLen int32
		err = binary.Read(buf, binary.BigEndian, &kdfTypeLen)
		if err != nil {
			return nil, err
		}

		kdfTypeNameBytes := make([]byte, kdfTypeLen)
		n, err := buf.Read(kdfTypeNameBytes)
		if err != nil {
			return nil, err
		}
		if n != len(kdfTypeNameBytes) {
			return nil, fmt.Errorf("Wrong number of bytes read when deserializing kdf type name")
		}

		kdfType, ok := typeMap[string(kdfTypeNameBytes)]
		if !ok {
			return nil, fmt.Errorf("Cannot find kdf type with name: %v.", string(kdfTypeNameBytes))
		}
		result.Type = kdfType

		var kdfDataLen int32
		err = binary.Read(buf, binary.BigEndian, &kdfDataLen)
		if err != nil {
			return nil, err
		}

		kdfData := make([]byte, kdfDataLen)
		n, err = buf.Read(kdfData)
		if err != nil {
			return nil, err
		}
		if n != len(kdfData) {
			return nil, fmt.Errorf("Wrong number of bytes read when deserializing kdf data")
		}
		kdf, err := kdfType.Type.Deserialize(kdfData)
		if err != nil {
			return nil, err
		}
		result.Kdf = kdf

		var keyDataLen int32
		err = binary.Read(buf, binary.BigEndian, &keyDataLen)
		if err != nil {
			return nil, err
		}
		keyData := make([]byte, keyDataLen)
		n, err = buf.Read(keyData)
		if err != nil {
			return nil, err
		}
		if n != len(keyData) {
			return nil, fmt.Errorf("Wrong number of bytes read when deserializing key data")
		}
		key, err := ssc.DeserializeKey(keyData)
		if err != nil {
			return nil, err
		}
		wrappedKey, ok := key.Key.(KeySymmetric)
		if !ok {
			return nil, fmt.Errorf("Deserializing KDF: Key type is not a symmetric key")
		}
		keyBytes := wrappedKey.GetKey()
		if keyBytes != nil && len(keyBytes) > 0 {
			return nil, fmt.Errorf("Deserializing KDF: Embedded key should not contain actual key bytes")
		}
		result.Key = key
	default:
		return nil, fmt.Errorf("Invalid kdf version: %v", ver.GetVersion())
	}

	return result, nil
}

func (k *StrongSaltKdf) GenerateKey(password []byte) (*ssc.StrongSaltKey, error) {
	key, ok := k.Key.Key.(KeySymmetric)
	if !ok {
		return nil, fmt.Errorf("KDF key does not implement KeySymmetric interface.")
	}
	keyBytes, err := k.Kdf.GenerateKey(password, key.KeyLen())
	if err != nil {
		return nil, err
	}
	err = key.SetKey(keyBytes)
	if err != nil {
		return nil, err
	}
	return k.Key, nil
}
