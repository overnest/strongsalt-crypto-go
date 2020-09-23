package kdf

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	. "github.com/overnest/strongsalt-crypto-go/interfaces"
	"github.com/overnest/strongsalt-crypto-go/version"
	"golang.org/x/crypto/argon2"
)

const (
	versionTypeName = "Argon2Version"
	defaultIter     = int32(1)
	defaultMemory   = int32(64 * 1024)
	defaultThreads  = int32(1) // DO NOT CHANGE libsodium only supports 1 thread
	defaultSaltLen  = 16
)

/*
** Version
 */
var (
	VERSION_ONE = newArgon2Version("ONE", 1)
	curVersion  = VERSION_ONE
)

type Argon2Version struct {
	Name    string
	Version version.Version
}

func (kv *Argon2Version) GetVersion() version.Version {
	return kv.Version
}

var versionMap map[int32]version.VersionInterface = make(map[int32]version.VersionInterface)

func newArgon2Version(name string, ver int32) *Argon2Version {
	kdfVersion := &Argon2Version{name, version.Version(ver)}
	versionMap[ver] = kdfVersion
	return kdfVersion
}

func init() {
	version.SetClassVersions(versionTypeName, versionMap)
}

/*
** Main
 */
type Argon2 struct {
	version *Argon2Version
	salt    []byte
	iter    int32
	memory  int32
}

func (_ *Argon2) New() (KdfBase, error) {
	salt := make([]byte, defaultSaltLen)
	n, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	if n != len(salt) {
		return nil, fmt.Errorf("Wrong number of random bytes read while generating salt")
	}
	return &Argon2{
		version: curVersion,
		salt:    salt,
		iter:    defaultIter,
		memory:  defaultMemory,
	}, nil
}

// The serialization/deserialization format is as follows:

// Version 1:
// ---------------------------------------------------------------------------------------------------------------
// | version(4 bytes) | saltLen(4 bytes) | salt | iterLen(4 bytes) | iter(4 bytes) | memoryLen(4 bytes) | memory |
// ---------------------------------------------------------------------------------------------------------------

func (_ *Argon2) Deserialize(data []byte) (KdfBase, error) {
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
	ver := genericVer.(*Argon2Version)
	result := &Argon2{}
	switch ver {
	case VERSION_ONE:
		// salt
		var saltLen int32
		err := binary.Read(buf, binary.BigEndian, &saltLen)
		if err != nil {
			return nil, err
		}
		salt := make([]byte, saltLen)
		n, err := buf.Read(salt)
		if err != nil {
			return nil, err
		}
		if n != len(salt) {
			return nil, fmt.Errorf("wrong number of bytes read when deserializing salt")
		}
		result.salt = salt
		// iter
		_ = buf.Next(4)
		var iter int32
		err = binary.Read(buf, binary.BigEndian, &iter)
		if err != nil {
			return nil, err
		}
		result.iter = iter
		// memory
		_ = buf.Next(4)
		var memory int32
		err = binary.Read(buf, binary.BigEndian, &memory)
		if err != nil {
			return nil, err
		}
		result.memory = memory
	}
	return result, nil
}

func (k *Argon2) Serialize() ([]byte, error) {
	ver := version.Serialize(k.version)
	switch k.version {
	case VERSION_ONE:
		// version
		buf := bytes.NewBuffer(nil)
		buf.Write(ver)
		// salt
		err := binary.Write(buf, binary.BigEndian, int32(len(k.salt)))
		if err != nil {
			return nil, err
		}
		buf.Write(k.salt)
		// iter
		err = binary.Write(buf, binary.BigEndian, int32(4))
		if err != nil {
			return nil, err
		}
		err = binary.Write(buf, binary.BigEndian, k.iter)
		if err != nil {
			return nil, err
		}
		// memory
		err = binary.Write(buf, binary.BigEndian, int32(4))
		if err != nil {
			return nil, err
		}
		err = binary.Write(buf, binary.BigEndian, k.memory)
		if err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	return nil, nil
}

func (k *Argon2) GenerateKey(password []byte, keyLen int) ([]byte, error) {
	return argon2.IDKey(password, k.salt, uint32(k.iter), uint32(k.memory), uint8(defaultThreads), uint32(keyLen)), nil
}
