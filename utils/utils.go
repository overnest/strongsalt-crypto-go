package utils

import (
	"bytes"
	"encoding/binary"
)

const KeyLengthSerialSize = 4

func KeySymmetricSerialize(key, ver []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(ver)
	binary.Write(buf, binary.BigEndian, int32(len(key)))
	buf.Write(key)

	return buf.Bytes(), nil
}
