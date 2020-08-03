package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"

	ssc "github.com/overnest/strongsalt-crypto-go"
	"github.com/overnest/strongsalt-crypto-go/kdf"
)

const (
	address = "localhost:8084"
)

var (
	transactionCount = 0

	transactions map[int]*ssc.StrongSaltKey = make(map[int]*ssc.StrongSaltKey)
)

type cryptoData struct {
	Transaction int    `json:"transaction,omitempty"`
	Password    string `json:"password,omitempty"`
	SerialData  string `json:"key,omitempty"`
	Plaintext   string `json:"plaintext,omitempty"`
	Ciphertext  string `json:"ciphertext,omitempty"`
	MAC         string `json:"mac,omitempty"`
}

func validateReceived(reqData *cryptoData, key *ssc.StrongSaltKey) string {
	ciphertext, err := base64.URLEncoding.DecodeString(reqData.Ciphertext)
	if err != nil {
		log.Printf("Error decoding base64 ciphertext string: %v", err)
	}
	if reqData.Plaintext != "" {
		// plaintext means we want to decrypt
		if !key.Key.CanDecrypt() {
			return fmt.Sprintf("deserialized key cannot decrypt, but request contains plaintext")
		}
		plaintext, err := key.Decrypt(ciphertext)
		if err != nil {
			return fmt.Sprintf("Error decrypting ciphertext: %v", err)
		}
		correctPlaintext, err := base64.URLEncoding.DecodeString(reqData.Plaintext)
		if err != nil {
			return fmt.Sprintf("Error decoding base64 plaintext string: %v", err)
		}
		if !bytes.Equal(plaintext, correctPlaintext) {
			return fmt.Sprintf("Decrypted ciphertext does not match given plaintext")
		}
	} else if reqData.MAC != "" {
		// no plaintext means are are checking a MAC
		if !key.CanMAC() {
			return fmt.Sprintf("key is not a MAC key, but no plaintext was given")
		}
		_, err := key.MACWrite(ciphertext)
		if err != nil {
			return fmt.Sprintf("error writing data for MAC key: %v", err)
		}
		mac, err := base64.URLEncoding.DecodeString(reqData.MAC)
		if err != nil {
			return fmt.Sprintf("error decoding base64 MAC string: %v", err)
		}
		ok, err := key.MACVerify(mac)
		if err != nil {
			return fmt.Sprintf("error verifying MAC: %v", err)
		} else if !ok {
			return fmt.Sprintf("MAC verification returned false")
		}
	} else {
		if !key.IsAsymmetric() {
			return fmt.Sprintf("No plaintext or MAC was sent, but key is not an asymmetric key.")
		} else if key.CanDecrypt() {
			return fmt.Sprintf("No plaintext or MAC was sent, but key contains a private key.")
		}
	}
	return ""
}

func genCryptoData(key *ssc.StrongSaltKey) (*cryptoData, error) {
	data := &cryptoData{}

	message := make([]byte, 64*5)
	rand.Read(message)
	if key.Key.CanEncrypt() {
		data.Plaintext = base64.URLEncoding.EncodeToString(message)

		ciphertext, err := key.Encrypt(message)
		if err != nil {
			return nil, err
		}
		data.Ciphertext = base64.URLEncoding.EncodeToString(ciphertext)
	} else if key.CanMAC() {
		key.MACReset()

		data.Ciphertext = base64.URLEncoding.EncodeToString(message)

		_, err := key.MACWrite(message)
		if err != nil {
			return nil, err
		}
		mac, err := key.MACSum(nil)
		if err != nil {
			return nil, err
		}
		data.MAC = base64.URLEncoding.EncodeToString(mac)
	}

	return data, nil
}

func deserializeKdf(serializedKdf []byte, password string) (*ssc.StrongSaltKey, error) {
	kdf, err := kdf.DeserializeKdf(serializedKdf)
	if err != nil {
		return nil, err
	}

	key, err := kdf.GenerateKey([]byte(password))
	if err != nil {
		return nil, err
	}

	return key, nil
}

func pushTransaction(w http.ResponseWriter, req *http.Request) {
	reqData := &cryptoData{}

	err := json.NewDecoder(req.Body).Decode(reqData)
	if err != nil {
		msg := fmt.Sprintf("PUSH: Error decoding request json: %v", err)
		log.Printf(msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
	}
	serializedKey, err := base64.URLEncoding.DecodeString(reqData.SerialData)
	if err != nil {
		msg := fmt.Sprintf("PUSH: Error decoding base64 key string: %v", err)
		log.Printf(msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
	}
	var key *ssc.StrongSaltKey

	if reqData.Password != "" {
		key, err = deserializeKdf(serializedKey, reqData.Password)
		if err != nil {
			msg := fmt.Sprintf("PUSH: Error deserializing KDF: %v", err)
			log.Printf(msg)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(msg))
			return
		}
	} else {
		key, err = ssc.DeserializeKey(serializedKey)
		if err != nil {
			msg := fmt.Sprintf("PUSH: error deserializing key: %v", err)
			log.Printf(msg)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(msg))
			return
		}
	}

	msg := validateReceived(reqData, key)
	if msg != "" {
		msg = "PUSH: " + msg
		log.Printf(msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
	}

	resData, err := genCryptoData(key)
	if err != nil {
		msg := fmt.Sprintf("PUSH: error generating data for response: %v", err)
		log.Printf(msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
	}

	resJson, err := json.Marshal(resData)
	if err != nil {
		msg := fmt.Sprintf("PUSH: error encoding response as json: %v", err)
		log.Printf(msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
	}

	w.Write(resJson)
}

func pullTransaction(w http.ResponseWriter, req *http.Request) {
	var typeStruct struct {
		KeyType    string
		PublicOnly bool
		KdfType    string
	}
	err := json.NewDecoder(req.Body).Decode(&typeStruct)
	if err != nil {
		msg := fmt.Sprintf("PULL: Error decoding request json: %v", err)
		log.Printf(msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
	}

	keyType := ssc.TypeFromName(typeStruct.KeyType)
	if keyType == nil {
		msg := fmt.Sprintf("PULL: There is no key type named: %v", typeStruct.KeyType)
		log.Printf(msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
	}
	var key *ssc.StrongSaltKey
	var sscKdf *kdf.StrongSaltKdf
	var password string

	if typeStruct.KdfType != "" {
		kdfType := kdf.TypeFromName(typeStruct.KdfType)
		if kdfType == nil {
			msg := fmt.Sprintf("PULL: There is no kdf type named: %v", typeStruct.KdfType)
			log.Printf(msg)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(msg))
			return
		}
		sscKdf, err = kdf.New(kdfType, keyType)
		if err != nil {
			msg := fmt.Sprintf("PULL: New KDF Error: %v", err)
			log.Printf(msg)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(msg))
			return
		}
		passNum, _ := rand.Int(rand.Reader, big.NewInt(1024))
		password = "password" + passNum.String()

		key, err = sscKdf.GenerateKey([]byte(password))
		if err != nil {
			msg := fmt.Sprintf("PULL: KDF generate key Error: %v", err)
			log.Printf(msg)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(msg))
			return
		}
	} else {
		key, err = ssc.GenerateKey(keyType)
		if err != nil {
			msg := fmt.Sprintf("PULL: Error generating key of type %v: %v", typeStruct.KeyType, err)
			log.Printf(msg)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(msg))
			return
		}
	}

	var resData *cryptoData
	if !typeStruct.PublicOnly {
		resData, err = genCryptoData(key)
		if err != nil {
			msg := fmt.Sprintf("PULL: error generating data for response: %v", err)
			log.Printf(msg)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(msg))
			return
		}
	}

	if sscKdf != nil {
		serialKdf, err := sscKdf.Serialize()
		if err != nil {
			msg := fmt.Sprintf("PULL: error serializing kdf: %v", err)
			log.Printf(msg)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(msg))
			return
		}
		resData.SerialData = base64.URLEncoding.EncodeToString(serialKdf)
		resData.Password = password
	} else if typeStruct.PublicOnly {
		resData = &cryptoData{}
		serializedKey, err := key.SerializePublic()
		if err != nil {
			msg := fmt.Sprintf("PULL: error serializing public key: %v", err)
			log.Printf(msg)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(msg))
			return
		}
		resData.SerialData = base64.URLEncoding.EncodeToString(serializedKey)
	} else {
		serializedKey, err := key.Serialize()
		if err != nil {
			msg := fmt.Sprintf("PULL: error serializing key: %v", err)
			log.Printf(msg)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(msg))
			return
		}
		resData.SerialData = base64.URLEncoding.EncodeToString(serializedKey)
	}

	transactionCount += 1
	resData.Transaction = transactionCount

	resJson, err := json.Marshal(resData)
	if err != nil {
		msg := fmt.Sprintf("PULL: error encoding response as json: %v", err)
		log.Printf(msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
	}

	transactions[transactionCount] = key

	w.Write(resJson)
}

func pullResponse(w http.ResponseWriter, req *http.Request) {
	reqData := &cryptoData{}

	err := json.NewDecoder(req.Body).Decode(reqData)
	if err != nil {
		msg := fmt.Sprintf("PULLRESPONSE: Error decoding request json: %v", err)
		log.Printf(msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
	}

	if reqData.Plaintext == "" && reqData.MAC == "" {
		// This response means that something went wrong on the other end
		w.Write([]byte(""))
		return
	}

	key := transactions[reqData.Transaction]
	if key == nil {
		msg := fmt.Sprintf("PULLRESPONSE: Cannot find transaction %v", reqData.Transaction)
		log.Printf(msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
	}

	msg := validateReceived(reqData, key)
	if msg != "" {
		log.Printf(msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
	}

	w.Write([]byte(""))
}

func initializeMux(mux *http.ServeMux) error {
	mux.HandleFunc("/push", pushTransaction)
	mux.HandleFunc("/pull", pullTransaction)
	mux.HandleFunc("/pullResponse", pullResponse)
	return nil
}

func main() {
	mux := http.NewServeMux()
	initializeMux(mux)

	server := &http.Server{
		Addr:    address,
		Handler: mux,
	}
	err := server.ListenAndServe()
	if err != nil {
		log.Printf("Error starting server: %v", err)
	}
}
