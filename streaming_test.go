package strongsaltcrypto

import (
	"crypto/rand"
	"io/ioutil"
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
	encryptor.CloseWrite()

	ciphertext := make([]byte, len(plaintext)+5)
	nC, err := encryptor.Read(ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, len(plaintext), nC)
	ciphertext = ciphertext[:nC]

	firstHalfNonce := nonce[0 : len(nonce)/2]
	secondHalfNonce := nonce[len(nonce)/2:]
	n1, err := decryptor.Write(firstHalfNonce)
	assert.NoError(t, err)
	assert.Equal(t, n1, len(nonce)/2)
	toBeWrite := append(secondHalfNonce, ciphertext...)
	n2, err := decryptor.Write(toBeWrite)
	assert.NoError(t, err)
	assert.Equal(t, len(toBeWrite), n2)

	err = decryptor.CloseWrite()
	assert.NoError(t, err)

	decrypted := make([]byte, len(plaintext)+5)
	n3, err := decryptor.Read(decrypted)
	assert.NoError(t, err)
	assert.Equal(t, len(plaintext), n3)
	assert.Equal(t, decrypted[:n3], plaintext)
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
	err = encryptor.CloseWrite()
	assert.NoError(t, err)

	buf1 := make([]byte, blockSize/2)
	n1, err := encryptor.Read(buf1) // buffer size < available bytes
	assert.Equal(t, n1, blockSize/2)
	assert.NoError(t, err)

	buf2 := make([]byte, blockSize)
	n2, err := encryptor.Read(buf2) // buffer size > available bytes
	assert.Equal(t, n2, blockSize/2)
	buf2 = buf2[0:n2] // truncate to real cipher
	assert.NoError(t, err)

	remainingCipher, err := ioutil.ReadAll(encryptor)
	assert.NoError(t, err)
	assert.Equal(t, len(remainingCipher), 0)

	ciphertext := append(buf1, buf2...)

	n, err := decryptor.Write(ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, n, blockSize)

	err = decryptor.CloseWrite()
	assert.NoError(t, err)

	decrypted := make([]byte, blockSize+5)
	n3, err := decryptor.Read(decrypted)
	assert.Equal(t, blockSize, n3)
	assert.Equal(t, plaintext, decrypted[:n3])
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
	err = encryptor.CloseWrite()
	assert.NoError(t, err)

	lastEncrypted, err := ioutil.ReadAll(encryptor)
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
	err = decryptor.CloseWrite()
	assert.NoError(t, err)

	//lastDecrypted, err := decryptor.ReadLast()
	lastDecrypted, err := ioutil.ReadAll(decryptor)
	assert.NoError(t, err)
	decrypted = append(decrypted, lastDecrypted...)
	assert.Equal(t, len(decrypted), testPlaintextLen)
	assert.Equal(t, decrypted, originalText)
}
