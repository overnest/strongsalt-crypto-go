package kdf

import (
	"bytes"
	"testing"

	ssc "github.com/overnest/strongsalt-crypto-go"
	. "github.com/overnest/strongsalt-crypto-go/interfaces"
	"github.com/stretchr/testify/assert"
)

var (
	keyTypes []*ssc.KeyType = []*ssc.KeyType{ssc.Type_Secretbox, ssc.Type_XChaCha20}
	kdfTypes []*KdfType     = []*KdfType{Type_Pbkdf2, Type_Argon2}
)

func TestKdf(t *testing.T) {
	password := []byte("PassWord123")
	plaintext := []byte("This is a sentence.")

	for _, kdfType := range kdfTypes {
		for _, keyType := range keyTypes {
			kdf1, err := New(kdfType, keyType)
			assert.NoError(t, err)

			key, err := kdf1.GenerateKey(password)
			assert.NoError(t, err)

			ciphertext, err := key.Encrypt(plaintext)
			assert.NoError(t, err)

			decrypted, err := key.Decrypt(ciphertext)
			assert.NoError(t, err)
			assert.True(t, bytes.Equal(plaintext, decrypted))

			// Serialization
			serialKdf, err := kdf1.Serialize()
			assert.NoError(t, err)

			kdf2, err := DeserializeKdf(serialKdf)
			assert.NoError(t, err)

			kdfKey, ok := kdf2.Key.Key.(KeySymmetric)
			assert.True(t, ok)
			kdfKeyBytes := kdfKey.GetKey()
			assert.True(t, kdfKeyBytes == nil || len(kdfKeyBytes) == 0)

			key2, err := kdf2.GenerateKey(password)
			assert.NoError(t, err)

			decrypted2, err := key2.Decrypt(ciphertext)
			assert.NoError(t, err)
			assert.True(t, bytes.Equal(plaintext, decrypted2))
		}
	}
}
