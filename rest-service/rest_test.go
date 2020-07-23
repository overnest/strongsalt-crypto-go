package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	ssc "github.com/overnest/strongsalt-crypto-go"
	"github.com/stretchr/testify/assert"
)

var typeNames []string = []string{
	"Secretbox",
	"X25519",
	"XChaCha20",
	"HMACSha512",
}

func validateResponse(t *testing.T, key *ssc.StrongSaltKey, typeName string, resData *cryptoData) {
	if key.CanMAC() {
		key.MACReset()

		ciphertext, err := base64.URLEncoding.DecodeString(resData.Ciphertext)
		assert.NoError(t, err, typeName)

		n, err := key.MACWrite(ciphertext)
		assert.Equal(t, len(ciphertext), n, typeName)
		assert.NoError(t, err, typeName)

		correctMAC, err := base64.URLEncoding.DecodeString(resData.MAC)
		assert.NoError(t, err, typeName)
		ok, err := key.MACVerify(correctMAC)
		assert.NoError(t, err, typeName)
		assert.True(t, ok, typeName)
	} else {
		assert.NotEmpty(t, resData.Plaintext, typeName)
		correctPlaintext, err := base64.URLEncoding.DecodeString(resData.Plaintext)
		assert.NoError(t, err, typeName)

		ciphertext, err := base64.URLEncoding.DecodeString(resData.Ciphertext)
		assert.NoError(t, err, typeName)

		plaintext, err := key.Decrypt(ciphertext)
		assert.NoError(t, err, typeName)

		assert.True(t, bytes.Equal(plaintext, correctPlaintext), typeName)
	}
}

func buildRequest(t *testing.T, key *ssc.StrongSaltKey, typeName string) *cryptoData {
	keySerialization, err := key.Serialize()
	assert.NoError(t, err, typeName)

	req := &cryptoData{}

	req.Key = base64.URLEncoding.EncodeToString(keySerialization)

	message := make([]byte, 64*5)
	n, err := rand.Read(message)
	assert.Equal(t, len(message), n, typeName)
	assert.NoError(t, err, typeName)

	if key.CanMAC() {
		req.Ciphertext = base64.URLEncoding.EncodeToString(message)

		n, err := key.MACWrite(message)
		assert.Equal(t, len(message), n, typeName)
		assert.NoError(t, err, typeName)

		mac, err := key.MACSum(nil)
		assert.NoError(t, err, typeName)

		req.MAC = base64.URLEncoding.EncodeToString(mac)
	} else {
		assert.True(t, key.Key.CanEncrypt(), typeName)

		req.Plaintext = base64.URLEncoding.EncodeToString(message)

		ciphertext, err := key.Encrypt(message)
		assert.NoError(t, err, typeName)

		req.Ciphertext = base64.URLEncoding.EncodeToString(ciphertext)
	}

	return req
}
func TestPush(t *testing.T) {
	for _, typeName := range typeNames {
		keyType := ssc.TypeFromName(typeName)
		key, err := ssc.GenerateKey(keyType)
		assert.NoError(t, err, typeName)

		req := buildRequest(t, key, typeName)

		reqJson, err := json.Marshal(req)
		assert.NoError(t, err, typeName)

		client := &http.Client{}

		res, err := client.Post("http://"+address+"/push", "application/json", bytes.NewReader(reqJson))
		assert.NoError(t, err, typeName)

		assert.NotEqual(t, http.StatusInternalServerError, res.StatusCode, typeName)

		resData := &cryptoData{}
		err = json.NewDecoder(res.Body).Decode(resData)
		assert.NoError(t, err, typeName)

		validateResponse(t, key, typeName, resData)
	}
}

func TestPull(t *testing.T) {
	for _, typeName := range typeNames {
		var typeStruct struct {
			Type string
		}
		typeStruct.Type = typeName

		reqJson, err := json.Marshal(typeStruct)
		assert.NoError(t, err, typeName)

		client := &http.Client{}

		res, err := client.Post("http://"+address+"/pull", "application/json", bytes.NewReader(reqJson))
		assert.NoError(t, err, typeName)

		assert.NotEqual(t, http.StatusInternalServerError, res.StatusCode, typeName)
		resData := &cryptoData{}
		err = json.NewDecoder(res.Body).Decode(resData)
		assert.NoError(t, err, typeName)

		keySerialization, err := base64.URLEncoding.DecodeString(resData.Key)
		assert.NoError(t, err, typeName)
		key, err := ssc.DeserializeKey(keySerialization)
		assert.NoError(t, err, typeName)

		validateResponse(t, key, typeName, resData)

		if t.Failed() {
			return
		}

		transaction := resData.Transaction

		req := buildRequest(t, key, typeName)
		req.Transaction = transaction

		reqJson, err = json.Marshal(req)
		assert.NoError(t, err, typeName)

		res, err = client.Post("http://"+address+"/pullResponse", "application/json", bytes.NewReader(reqJson))
		assert.NoError(t, err, typeName)

		assert.NotEqual(t, http.StatusInternalServerError, res.StatusCode, typeName)
	}
}
