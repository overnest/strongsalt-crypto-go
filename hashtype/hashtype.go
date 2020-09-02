package hashtype

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

type HashType struct {
	Name     string
	HashFunc func() hash.Hash
}

var (
	hashTypeMap map[string]*HashType = make(map[string]*HashType)

	TypeSha256 *HashType = newHashType("sha256", sha256.New)
	TypeSha512 *HashType = newHashType("sha512", sha512.New)
)

func newHashType(name string, hashFunc func() hash.Hash) *HashType {
	hashType := &HashType{name, hashFunc}
	hashTypeMap[name] = hashType
	return hashType
}

func (h *HashType) Serialize() ([]byte, error) {
	return []byte(h.Name), nil
}

func DeserializeHashType(data []byte) (*HashType, error) {
	hashTypeName := string(data)
	hashType, exists := hashTypeMap[hashTypeName]
	if !exists {
		return nil, fmt.Errorf("Cannot find hash type: %v.", hashTypeName)
	}
	return hashType, nil
}
