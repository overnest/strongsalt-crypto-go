package hmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/overnest/strongsalt-crypto-go/hashtype"
	. "github.com/overnest/strongsalt-crypto-go/interfaces"
	"github.com/overnest/strongsalt-crypto-go/version"
)

/*
** VERSION
 */

const (
	versionTypeName       = "HmacKeyVersion"
	hashTypeLenSerialSize = 2
	keyLenSerialSize      = 4
)

var (
	VERSION_ONE = newHmacKeyVersion("ONE", 1)
	curVersion  = VERSION_ONE
)

type HmacKeyVersion struct {
	Name    string
	Version version.Version
}

func (kv *HmacKeyVersion) GetVersion() version.Version {
	return kv.Version
}

var keyVersionMap map[int32]version.VersionInterface = make(map[int32]version.VersionInterface)

func newHmacKeyVersion(name string, ver int32) *HmacKeyVersion {
	keyVersion := &HmacKeyVersion{name, version.Version(ver)}
	keyVersionMap[ver] = keyVersion
	return keyVersion
}

func init() {
	version.SetClassVersions(versionTypeName, keyVersionMap)
}

/*
** MAIN
 */

type HmacKey struct {
	hmac     hash.Hash
	HashType *hashtype.HashType
	KeyLen   int32
	key      []byte
	version  *HmacKeyVersion
}

func (k *HmacKey) GenerateKey() (KeyBase, error) {
	hashType := k.HashType
	key := make([]byte, k.KeyLen)
	n, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	if n != len(key) {
		return nil, fmt.Errorf("hmac generate key returned wrong number of bytes")
	}
	hmac := hmac.New(hashType.HashFunc, key)
	return &HmacKey{
		hmac:     hmac,
		HashType: hashType,
		key:      key,
		KeyLen:   k.KeyLen,
		version:  curVersion,
	}, nil
}

// The serialization/deserialization format is as follows:
//
// Version 1:
//  -----------------------------------------------------------------------------
// | version(4 bytes) | hashTypeLen(4 bytes) | hashType | keyLen(4 bytes) | key |
//  -----------------------------------------------------------------------------
//

func (k *HmacKey) CanEncrypt() bool {
	return false
}

func (k *HmacKey) CanDecrypt() bool {
	return false
}

func (k *HmacKey) CanMAC() bool {
	return k.hmac != nil
}

func (k *HmacKey) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	ver := version.Serialize(k.version)
	buf.Write(ver)
	err := binary.Write(buf, binary.BigEndian, int32(len(k.HashType.Name)))
	if err != nil {
		return nil, err
	}
	hashType, err := k.HashType.Serialize()
	if err != nil {
		return nil, err
	}
	n, err := buf.Write(hashType)
	if err != nil {
		return nil, err
	}
	if n != len(hashType) {
		return nil, fmt.Errorf("wrong number of bytes written when serializing hash type")
	}
	err = binary.Write(buf, binary.BigEndian, k.KeyLen)
	if err != nil {
		return nil, err
	}
	buf.Write(k.key)

	return buf.Bytes(), nil
}

func (k *HmacKey) Deserialize(data []byte) (KeyBase, error) {
	versionBytes := data[:version.VersionSerialSize]
	genericVer, err := version.Deserialize(versionTypeName, versionBytes)
	if err != nil {
		return nil, err
	}
	ver := genericVer.(*HmacKeyVersion)

	var hashType *hashtype.HashType
	var key []byte
	buf := bytes.NewBuffer(data[version.VersionSerialSize:])
	switch ver {
	case VERSION_ONE:
		var hashTypeLen int32
		err := binary.Read(buf, binary.BigEndian, &hashTypeLen)
		if err != nil {
			return nil, err
		}
		hashTypeBytes := make([]byte, hashTypeLen)
		n, err := buf.Read(hashTypeBytes)
		if err != nil {
			return nil, err
		}
		if n != int(hashTypeLen) {
			return nil, fmt.Errorf("read wrong number of bytes when deserializing hash type")
		}
		hashType, err = hashtype.DeserializeHashType(hashTypeBytes)
		if err != nil {
			return nil, err
		}
		var keyLen int32
		err = binary.Read(buf, binary.BigEndian, &keyLen)
		if err != nil {
			return nil, err
		}
		key = make([]byte, keyLen)
		n, err = buf.Read(key)
		if err != nil {
			return nil, err
		}
		if n != len(key) {
			return nil, fmt.Errorf("Read wrong number of bytes when deserializing key")
		}
	default:
		return nil, fmt.Errorf("Unknown key version %v", ver.GetVersion().GetVersion())
	}
	return &HmacKey{
		key:      key,
		KeyLen:   int32(len(key)),
		version:  ver,
		HashType: hashType,
		hmac:     hmac.New(hashType.HashFunc, key),
	}, nil
}

func (k *HmacKey) Write(data []byte) (int, error) {
	return k.hmac.Write(data)
}

func (k *HmacKey) Sum(data []byte) ([]byte, error) {
	return k.hmac.Sum(data), nil
}

func (k *HmacKey) Verify(tag []byte) (bool, error) {
	thisTag, err := k.Sum(nil)
	if err != nil {
		return false, err
	}
	return hmac.Equal(thisTag, tag), nil
}

func (k *HmacKey) Reset() {
	k.hmac.Reset()
}
