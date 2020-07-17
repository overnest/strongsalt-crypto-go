package version

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	VersionSerialSize = 4
)

var classVersionMap map[string]map[int32]VersionInterface = make(map[string]map[int32]VersionInterface)

type Version int32

func (v Version) Serialize() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, v.GetVersion())
	return buf.Bytes()
}

func (v Version) GetVersion() int32 {
	return int32(v)
}

type VersionInterface interface {
	GetVersion() Version
}

func SetClassVersions(className string, versionMap map[int32]VersionInterface) error {
	_, exists := classVersionMap[className]
	if exists {
		return fmt.Errorf("Duplicate version class name: %v", className)
	}
	classVersionMap[className] = versionMap
	return nil
}

func GetClassVersion(className string, version Version) (VersionInterface, error) {
	classVersions, exists := classVersionMap[className]
	if !exists {
		return nil, fmt.Errorf("Cannot find versions for class %v", className)
	}
	ver, exists := classVersions[version.GetVersion()]
	if !exists {
		return nil, fmt.Errorf("Cannot find version %v for class %v", version, className)
	}
	return ver, nil
}

func Serialize(ver VersionInterface) []byte {
	return ver.GetVersion().Serialize()
}

func Deserialize(className string, data []byte) (VersionInterface, error) {
	buf := bytes.NewBuffer(data)
	//verNum, n, err := buf.ReadRune()
	var verNum uint32
	err := binary.Read(buf, binary.LittleEndian, &verNum)
	if err != nil {
		return nil, err
	} /* else if n != VersionSerialSize {
		return nil, fmt.Errorf("Read wrong number of bytes while deserializing version")
	}*/
	ver := Version(verNum)
	keyVersion, err := GetClassVersion(className, ver)
	if err != nil {
		return nil, err
	}
	return keyVersion, nil
}
