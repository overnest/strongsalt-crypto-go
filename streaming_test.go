package strongsaltcrypto

import (
	"crypto/rand"
	random "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

const testPlaintextLen = 1000
const testSubLen = 20

func TestStreamingNonce(t *testing.T) {
	key, err := GenerateKey(Type_XChaCha20)
	assert.NoError(t, err)

	encryptor, err := key.EncryptStream()
	assert.NoError(t, err)
	decryptor, err := key.DecryptStream(0)
	assert.NoError(t, err)
	nonce := encryptor.GetNonce()
	blockSize := key.BlockSize()

	plaintext := make([]byte, blockSize)
	rand.Read(plaintext)
	encryptor.Write(plaintext)
	ciphertext, err := encryptor.ReadLast()
	assert.NoError(t, err)

	firstHalfNonce := nonce[0 : len(nonce)/2]
	secondHalfNonce := nonce[len(nonce)/2:]
	n1, err := decryptor.Write(firstHalfNonce)
	assert.NoError(t, err)
	assert.Equal(t, n1, len(nonce)/2)
	toBeWrite := append(secondHalfNonce, ciphertext...)
	n2, err := decryptor.Write(toBeWrite)
	assert.NoError(t, err)
	assert.Equal(t, len(toBeWrite), n2)

	encrypted, err := decryptor.ReadLast()
	assert.NoError(t, err)
	assert.Equal(t, encrypted, plaintext)
}

func TestStreamingBasic(t *testing.T) {
	key, err := GenerateKey(Type_XChaCha20)
	assert.NoError(t, err)

	encryptor, err := key.EncryptStream()
	assert.NoError(t, err)
	decryptor, err := key.DecryptStream(0)
	assert.NoError(t, err)
	blockSize := key.BlockSize()
	nonce := encryptor.nonce
	decryptor.Write(nonce)

	plaintext := make([]byte, blockSize)
	rand.Read(plaintext)

	originaltext := make([]byte, blockSize)
	copy(originaltext, plaintext)

	encryptor.Write(plaintext)

	buf1 := make([]byte, blockSize/2)
	n1, err := encryptor.Read(buf1) // buffer size < available bytes
	assert.Equal(t, n1, blockSize/2)
	assert.NoError(t, err)

	buf2 := make([]byte, blockSize)
	n2, err := encryptor.Read(buf2) // buffer size > available bytes
	assert.Equal(t, n2, blockSize/2)
	buf2 = buf2[0:n2] // truncate to real cipher
	assert.NoError(t, err)

	remainingCipher, err := encryptor.ReadLast()
	assert.NoError(t, err)
	assert.Equal(t, len(remainingCipher), 0)

	ciphertext := append(buf1, buf2...)

	n, err := decryptor.Write(ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, n, blockSize)

	decrypted, err := decryptor.ReadLast()
	assert.Equal(t, len(decrypted), blockSize)
	assert.Equal(t, plaintext, decrypted)
}

func TestStreamingAdvanced(t *testing.T) {
	key, err := GenerateKey(Type_XChaCha20)
	assert.NoError(t, err)

	encryptor, err := key.EncryptStream()
	assert.NoError(t, err)
	decryptor, err := key.DecryptStream(0)
	assert.NoError(t, err)
	blockSize := key.BlockSize()
	nonce := encryptor.nonce
	decryptor.Write(nonce)

	plaintext := make([]byte, testPlaintextLen)
	rand.Read(plaintext)
	originalText := make([]byte, testPlaintextLen)
	copy(originalText, plaintext)

	// encryptor
	var encrypted []byte
	buf := make([]byte, blockSize)
	for len(plaintext) > 0 {
		subLen := random.Intn(testSubLen)
		if subLen > len(plaintext) {
			subLen = len(plaintext)
		}
		plain := plaintext[0:subLen]
		plaintext = plaintext[subLen:]
		_, err := encryptor.Write(plain)
		assert.NoError(t, err)
		n, err := encryptor.Read(buf)
		assert.NoError(t, err)
		encrypted = append(encrypted, buf[0:n]...)
	}
	lastEncrypted, err := encryptor.ReadLast()
	assert.NoError(t, err)
	encrypted = append(encrypted, lastEncrypted...)
	assert.Equal(t, len(encrypted), testPlaintextLen)

	// decryptor
	var decrypted []byte
	for len(encrypted) > 0 {
		subLen := random.Intn(testSubLen)
		if subLen > len(encrypted) {
			subLen = len(encrypted)
		}
		cipher := encrypted[0:subLen]
		encrypted = encrypted[subLen:]
		_, err := decryptor.Write(cipher)
		assert.NoError(t, err)
		n, err := decryptor.Read(buf)
		assert.NoError(t, err)
		decrypted = append(decrypted, buf[0:n]...)
	}
	lastDecrypted, err := decryptor.ReadLast()
	assert.NoError(t, err)
	decrypted = append(decrypted, lastDecrypted...)
	assert.Equal(t, len(decrypted), testPlaintextLen)
	assert.Equal(t, decrypted, originalText)
}
