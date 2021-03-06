package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	ssc "github.com/overnest/strongsalt-crypto-go"
	"github.com/overnest/strongsalt-crypto-go/kdf"
	"github.com/overnest/strongsalt-crypto-go/pake/srp"
	"github.com/stretchr/testify/assert"
)

var keyTypeNames []string = []string{
	"SECRETBOX",
	"X25519",
	"XCHACHA20",
	"XCHACHA20HMAC",
	"HMACSHA512",
}

var symmetricKeyTypeNames []string = []string{
	"XCHACHA20",
	"XCHACHA20HMAC",
	"SECRETBOX",
}

var asymmetricKeyTypeNames []string = []string{
	"X25519",
}

var kdfTypeNames []string = []string{
	"PBKDF2",
	"ARGON2",
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
	}
	if key.CanDecrypt() {
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

func buildKeyRequest(t *testing.T, key *ssc.StrongSaltKey, typeName string) *cryptoData {
	keySerialization, err := key.Serialize()
	assert.NoError(t, err, typeName)

	req := &cryptoData{}

	req.SerialData = base64.URLEncoding.EncodeToString(keySerialization)

	message := make([]byte, 64*5)
	n, err := rand.Read(message)
	assert.Equal(t, len(message), n, typeName)
	assert.NoError(t, err, typeName)

	if key.CanEncrypt() {
		assert.True(t, key.Key.CanEncrypt(), typeName)

		req.Plaintext = base64.URLEncoding.EncodeToString(message)

		ciphertext, err := key.Encrypt(message)
		assert.NoError(t, err, typeName)

		req.Ciphertext = base64.URLEncoding.EncodeToString(ciphertext)
		message = ciphertext
	}
	if key.CanMAC() {
		if req.Ciphertext == "" {
			req.Ciphertext = base64.URLEncoding.EncodeToString(message)
		}

		err = key.MACReset()
		assert.NoError(t, err, typeName)

		n, err := key.MACWrite(message)
		assert.Equal(t, len(message), n, typeName)
		assert.NoError(t, err, typeName)

		mac, err := key.MACSum(nil)
		assert.NoError(t, err, typeName)

		req.MAC = base64.URLEncoding.EncodeToString(mac)
	}

	return req
}

func sendPush(t *testing.T, typeName string, req *cryptoData) *cryptoData {
	client := &http.Client{}

	reqJson, err := json.Marshal(req)
	assert.NoError(t, err, typeName)

	res, err := client.Post("http://"+address+"/push", "application/json", bytes.NewReader(reqJson))
	assert.NoError(t, err, typeName)

	assert.NotEqual(t, http.StatusInternalServerError, res.StatusCode, typeName)

	resData := &cryptoData{}
	err = json.NewDecoder(res.Body).Decode(resData)
	assert.NoError(t, err, typeName)

	return resData
}

func TestPushKeys(t *testing.T) {
	for _, typeName := range keyTypeNames {
		keyType := ssc.TypeFromName(typeName)
		key, err := ssc.GenerateKey(keyType)
		assert.NoError(t, err, typeName)

		req := buildKeyRequest(t, key, typeName)

		resData := sendPush(t, typeName, req)

		validateResponse(t, key, typeName, resData)
	}

	for _, typeName := range asymmetricKeyTypeNames {
		keyType := ssc.TypeFromName(typeName)
		key, err := ssc.GenerateKey(keyType)
		assert.NoError(t, err, typeName)

		req := &cryptoData{}

		keySerialization, err := key.SerializePublic()
		assert.NoError(t, err, typeName)

		req.SerialData = base64.URLEncoding.EncodeToString(keySerialization)

		resData := sendPush(t, typeName, req)

		validateResponse(t, key, typeName, resData)
	}
}

func TestPushKdfs(t *testing.T) {
	password := "ThIs is a p4ssw0rd"

	for _, kdfTypeName := range kdfTypeNames {
		kdfType := kdf.TypeFromName(kdfTypeName)
		for _, keyTypeName := range symmetricKeyTypeNames {
			fullName := kdfTypeName + " -> " + keyTypeName

			keyType := ssc.TypeFromName(keyTypeName)

			kdf1, err := kdf.New(kdfType, keyType)
			assert.NoError(t, err, fullName)

			key, err := kdf1.GenerateKey([]byte(password))
			assert.NoError(t, err, fullName)

			req := buildKeyRequest(t, key, fullName)

			serialKdf, err := kdf1.Serialize()
			assert.NoError(t, err, fullName)
			req.SerialData = base64.URLEncoding.EncodeToString(serialKdf)

			req.Password = password

			resData := sendPush(t, fullName, req)

			validateResponse(t, key, fullName, resData)
		}
	}
}

func sendPull(t *testing.T, typeName string, reqJson []byte) *cryptoData {
	client := &http.Client{}

	res, err := client.Post("http://"+address+"/pull", "application/json", bytes.NewReader(reqJson))
	assert.NoError(t, err, typeName)

	assert.NotEqual(t, http.StatusInternalServerError, res.StatusCode, typeName)
	resData := &cryptoData{}
	err = json.NewDecoder(res.Body).Decode(resData)
	assert.NoError(t, err, typeName)

	return resData
}

func sendPullResponse(t *testing.T, transaction int, key *ssc.StrongSaltKey, typeName string) {
	req := buildKeyRequest(t, key, typeName)
	req.Transaction = transaction

	reqJson, err := json.Marshal(req)
	assert.NoError(t, err, typeName)

	client := &http.Client{}

	res, err := client.Post("http://"+address+"/pullResponse", "application/json", bytes.NewReader(reqJson))
	assert.NoError(t, err, typeName)

	assert.NotEqual(t, http.StatusInternalServerError, res.StatusCode, typeName)
}

func TestPullKeys(t *testing.T) {
	for _, typeName := range keyTypeNames {
		var typeStruct struct {
			KeyType string
		}
		typeStruct.KeyType = typeName

		reqJson, err := json.Marshal(typeStruct)
		assert.NoError(t, err, typeName)

		resData := sendPull(t, typeName, reqJson)

		keySerialization, err := base64.URLEncoding.DecodeString(resData.SerialData)
		assert.NoError(t, err, typeName)
		key, err := ssc.DeserializeKey(keySerialization)
		assert.NoError(t, err, typeName)

		validateResponse(t, key, typeName, resData)

		if t.Failed() {
			return
		}

		if key.CanMAC() {
			key.MACReset()
		}

		transaction := resData.Transaction

		sendPullResponse(t, transaction, key, typeName)
	}

	for _, typeName := range asymmetricKeyTypeNames {
		var typeStruct struct {
			KeyType    string
			PublicOnly bool
		}

		typeStruct.KeyType = typeName
		typeStruct.PublicOnly = true

		reqJson, err := json.Marshal(typeStruct)
		assert.NoError(t, err, typeName)

		resData := sendPull(t, typeName, reqJson)

		keySerialization, err := base64.URLEncoding.DecodeString(resData.SerialData)
		assert.NoError(t, err, typeName)
		key, err := ssc.DeserializeKey(keySerialization)
		assert.NoError(t, err, typeName)

		transaction := resData.Transaction

		sendPullResponse(t, transaction, key, typeName)
	}
}

func TestPullKdfs(t *testing.T) {
	var typeStruct struct {
		KeyType string
		KdfType string
	}

	for _, kdfTypeName := range kdfTypeNames {
		for _, keyTypeName := range symmetricKeyTypeNames {
			fullName := kdfTypeName + " -> " + keyTypeName

			typeStruct.KdfType = kdfTypeName
			typeStruct.KeyType = keyTypeName

			reqJson, err := json.Marshal(typeStruct)
			assert.NoError(t, err, fullName)

			resData := sendPull(t, fullName, reqJson)

			kdfSerialization, err := base64.URLEncoding.DecodeString(resData.SerialData)
			assert.NoError(t, err, fullName)
			kdf1, err := kdf.DeserializeKdf(kdfSerialization)
			assert.NoError(t, err, fullName)

			key, err := kdf1.GenerateKey([]byte(resData.Password))
			validateResponse(t, key, fullName, resData)

			if t.Failed() {
				return
			}

			transaction := resData.Transaction

			sendPullResponse(t, transaction, key, fullName)
		}
	}
}

func TestSRP(t *testing.T) {
	srpSession, err := srp.NewFromVersion(1)
	assert.NoError(t, err)

	userID := "AliceBobberton"
	password := "Password123"

	verifier, err := srpSession.Verifier([]byte(userID), []byte(password))
	assert.NoError(t, err)

	srpUserID, verifierString := verifier.Encode()

	var verifierReq struct {
		UserID   string
		Verifier string
	}
	verifierReq.UserID = srpUserID
	verifierReq.Verifier = verifierString

	verifierJson, err := json.Marshal(&verifierReq)
	assert.NoError(t, err)

	client := &http.Client{}

	res, err := client.Post("http://"+address+"/srp/verifier", "application/json", bytes.NewReader(verifierJson))
	assert.NoError(t, err)
	assert.NotEqual(t, http.StatusInternalServerError, res.StatusCode)

	srpClient, err := srpSession.NewClient([]byte(userID), []byte(password))
	assert.NoError(t, err)

	creds := srpClient.Credentials()

	var initReq struct {
		Creds string
	}
	initReq.Creds = creds

	initJson, err := json.Marshal(&initReq)
	assert.NoError(t, err)

	res, err = client.Post("http://"+address+"/srp/init", "application/json", bytes.NewReader(initJson))
	assert.NoError(t, err)
	assert.NotEqual(t, http.StatusInternalServerError, res.StatusCode)

	var initRes struct {
		Creds string
	}
	err = json.NewDecoder(res.Body).Decode(&initRes)
	assert.NoError(t, err)

	proof, err := srpClient.Generate(initRes.Creds)
	assert.NoError(t, err)

	var proofReq struct {
		UserID string
		Proof  string
	}
	proofReq.UserID = srpUserID
	proofReq.Proof = proof

	proofJson, err := json.Marshal(&proofReq)
	assert.NoError(t, err)

	res, err = client.Post("http://"+address+"/srp/proof", "application/json", bytes.NewReader(proofJson))
	assert.NoError(t, err)
	assert.NotEqual(t, http.StatusInternalServerError, res.StatusCode)

	var proofRes struct {
		Proof string
	}
	err = json.NewDecoder(res.Body).Decode(&proofRes)
	assert.NoError(t, err)

	assert.True(t, srpClient.ServerOk(proofRes.Proof))
}
