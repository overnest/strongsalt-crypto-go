package strongsaltcrypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecretbox(t *testing.T) {
	key, err := GenerateKey(Type_Secretbox)
	assert.NoError(t, err)
	assert.True(t, key.IsSymmetric())

	data, err := key.Serialize()
	assert.NoError(t, err)
	newKey, err := DeserializeKey(data)
	assert.NoError(t, err)

	plaintext := []byte("This is a sentence.")
	ciphertext, err := key.Encrypt(plaintext)
	assert.NoError(t, err)

	decrypted, err := newKey.Decrypt(ciphertext)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(plaintext, decrypted))
}

func TestXChaCha20(t *testing.T) {
	key, err := GenerateKey(Type_XChaCha20)
	assert.NoError(t, err)
	assert.True(t, key.IsSymmetric())
	assert.True(t, key.IsMidstream())

	data, err := key.Serialize()
	assert.NoError(t, err)
	newKey, err := DeserializeKey(data)
	assert.NoError(t, err)

	blockSize := key.BlockSize()

	plaintext := make([]byte, blockSize*4+13)
	n, err := rand.Read(plaintext)
	assert.NoError(t, err)
	assert.Equal(t, len(plaintext), n)

	ciphertext, err := key.Encrypt(plaintext)
	assert.NoError(t, err)

	decrypted, err := newKey.Decrypt(ciphertext)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(plaintext, decrypted))

	blockNum := 3
	position := blockSize * blockNum

	nonce := ciphertext[:key.NonceSize()]
	ciphertext = ciphertext[key.NonceSize():]

	encryptedBlock, err := key.EncryptIC(plaintext[position:position+blockSize], nonce, uint32(blockNum))
	assert.True(t, bytes.Equal(ciphertext[position:position+blockSize], encryptedBlock))

	decryptedBlock, err := key.DecryptIC(ciphertext[position:position+blockSize], nonce, uint32(blockNum))
	assert.True(t, bytes.Equal(plaintext[position:position+blockSize], decryptedBlock))
}

func TestX25519(t *testing.T) {
	plaintext := []byte("dfadfja af8 ajdf adf0a fuda0df 0adjf88 d9fa0sdf afa233414 jdaf;")
	key, err := GenerateKey(Type_X25519)
	assert.NoError(t, err)

	assert.True(t, key.IsAsymmetric())

	data, err := key.Serialize()
	assert.NoError(t, err)
	newKey, err := DeserializeKey(data)
	assert.NoError(t, err)

	ciphertext, err := key.Encrypt(plaintext)
	assert.NoError(t, err)

	decrypted, err := newKey.Decrypt(ciphertext)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(plaintext, decrypted))

	// Public only
	serialPub, err := key.SerializePublic()
	assert.NoError(t, err)

	pubOnly, err := DeserializeKey(serialPub)
	assert.NoError(t, err)

	ciphertext2, err := pubOnly.Encrypt(plaintext)
	assert.NoError(t, err)

	decrypted2, err := key.Decrypt(ciphertext2)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(plaintext, decrypted2))
}

func TestMAC(t *testing.T) {
	key, err := GenerateKey(Type_HMACSha512)
	assert.NoError(t, err)
	assert.True(t, key.CanMAC())

	message := []byte("This is a message.")

	n, err := key.MACWrite(message)
	assert.NoError(t, err)
	assert.Equal(t, n, len(message))

	tag1, err := key.MACSum(nil)
	assert.NoError(t, err)

	key.MACReset()
	n, err = key.MACWrite(message)
	assert.NoError(t, err)
	assert.Equal(t, n, len(message))
	ok, err := key.MACVerify(tag1)
	assert.NoError(t, err)
	assert.True(t, ok)

	data, err := key.Serialize()
	assert.NoError(t, err)

	key2, err := DeserializeKey(data)
	assert.NoError(t, err)

	n, err = key2.MACWrite(message[:4])
	assert.NoError(t, err)
	assert.Equal(t, n, 4)

	n, err = key2.MACWrite(message[4:])
	assert.NoError(t, err)
	assert.Equal(t, n, len(message)-4)

	tag2, err := key2.MACSum(nil)
	assert.NoError(t, err)

	ok, err = key.MACVerify(tag2)
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, err = key2.MACVerify(tag1)
	assert.NoError(t, err)
	assert.True(t, ok)
}