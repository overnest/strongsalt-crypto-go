package pbkdf2

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/pbkdf2"

	"github.com/overnest/strongsalt-crypto-go/hashtype"
	. "github.com/overnest/strongsalt-crypto-go/interfaces"
	"github.com/overnest/strongsalt-crypto-go/version"
)

const (
	versionTypeName = "Pbkdf2Version"
	defaultIter     = uint32(100000)
	defaultSaltLen  = 16
)

var (
	defaultHashType = hashtype.TypeSha512
)

/*
** Version
 */

var (
	VERSION_ONE = newPbkdf2Version("ONE", 1)
	curVersion  = VERSION_ONE
)

type Pbkdf2Version struct {
	Name    string
	Version version.Version
}

func (kv *Pbkdf2Version) GetVersion() version.Version {
	return kv.Version
}

var versionMap map[int32]version.VersionInterface = make(map[int32]version.VersionInterface)

func newPbkdf2Version(name string, ver int32) *Pbkdf2Version {
	kdfVersion := &Pbkdf2Version{name, version.Version(ver)}
	versionMap[ver] = kdfVersion
	return kdfVersion
}

func init() {
	version.SetClassVersions(versionTypeName, versionMap)
}

/*
** Main
 */

type Pbkdf2 struct {
	version  *Pbkdf2Version
	hashType *hashtype.HashType
	salt     []byte
	iter     uint32
	//keyLen   int
}

func (_ *Pbkdf2) New() (KdfBase, error) {
	salt := make([]byte, defaultSaltLen)
	n, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	if n != len(salt) {
		return nil, fmt.Errorf("Wrong number of random bytes read while generating salt")
	}
	return &Pbkdf2{
		version:  curVersion,
		hashType: defaultHashType,
		salt:     salt,
		iter:     defaultIter,
	}, nil
}

// The serialization/deserialization format is as follows:
//
// Version 1:
//  --------------------------------------------------------------
// | version(4 bytes) | salt(16 bytes) | iter(4 bytes) | hashType |
//  --------------------------------------------------------------
//

func (_ *Pbkdf2) Deserialize(data []byte) (KdfBase, error) {
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
	ver := genericVer.(*Pbkdf2Version)
	result := &Pbkdf2{}
	switch ver {
	case VERSION_ONE:
		salt := make([]byte, 16)
		n, err := buf.Read(salt)
		if err != nil {
			return nil, err
		}
		if n != len(salt) {
			return nil, fmt.Errorf("wrong number of bytes read when deserializing salt")
		}
		result.salt = salt

		var iter uint32
		err = binary.Read(buf, binary.BigEndian, &iter)
		if err != nil {
			return nil, err
		}
		result.iter = iter

		hashType, err := hashtype.DeserializeHashType(buf.Bytes())
		if err != nil {
			return nil, err
		}
		result.hashType = hashType
	}
	return result, nil
}

func (k *Pbkdf2) Serialize() ([]byte, error) {
	ver := version.Serialize(k.version)
	switch k.version {
	case VERSION_ONE:
		buf := bytes.NewBuffer(nil)
		buf.Write(ver)
		buf.Write(k.salt)
		err := binary.Write(buf, binary.BigEndian, k.iter)
		if err != nil {
			return nil, err
		}
		hash, err := k.hashType.Serialize()
		if err != nil {
			return nil, err
		}
		buf.Write(hash)
		return buf.Bytes(), nil
	}
	return nil, nil
}

func (k *Pbkdf2) GenerateKey(password []byte, keyLen int) ([]byte, error) {
	return pbkdf2.Key(password, k.salt, int(k.iter), keyLen, k.hashType.HashFunc), nil
}
