package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	ssc "github.com/overnest/strongsalt-crypto-go"
)

const (
	address = "localhost:8084"
)

var (
	transactionCount = 0

	transactions map[int]*ssc.StrongSaltKey = make(map[int]*ssc.StrongSaltKey)
)

/*type transaction struct {
	key        *ssc.StrongSaltKey
	plaintext  []byte
	ciphertext []byte
}*/

type cryptoData struct {
	Transaction int
	Key         string
	Plaintext   string
	Ciphertext  string
	MAC         string
}

func validateReceived(reqData *cryptoData, key *ssc.StrongSaltKey) string {
	ciphertext, err := base64.URLEncoding.DecodeString(reqData.Ciphertext)
	if err != nil {
		log.Printf("PUSH: Error decoding base64 ciphertext string: %v", err)
	}
	if reqData.Plaintext != "" {
		// plaintext means we want to decrypt
		if !key.Key.CanDecrypt() {
			return fmt.Sprintf("PUSH: deserialized key cannot decrypt, but request contains plaintext")
		}
		plaintext, err := key.Decrypt(ciphertext)
		if err != nil {
			return fmt.Sprintf("PUSH: Error decrypting ciphertext: %v", err)
		}
		correctPlaintext, err := base64.URLEncoding.DecodeString(reqData.Plaintext)
		if err != nil {
			return fmt.Sprintf("PUSH: Error decoding base64 plaintext string: %v", err)
		}
		if !bytes.Equal(plaintext, correctPlaintext) {
			return fmt.Sprintf("PUSH: Decrypted ciphertext does not match given plaintext")
		}
	} else {
		// no plaintext means are are checking a MAC
		if !key.CanMAC() {
			return fmt.Sprintf("PUSH: key is not a MAC key, but no plaintext was given")
		}
		_, err := key.MACWrite(ciphertext)
		if err != nil {
			return fmt.Sprintf("PUSH: error writing data for MAC key: %v", err)
		}
		mac, err := base64.URLEncoding.DecodeString(reqData.MAC)
		if err != nil {
			return fmt.Sprintf("PUSH: error decoding base64 MAC string: %v", err)
		}
		ok, err := key.MACVerify(mac)
		if err != nil {
			return fmt.Sprintf("PUSH: error verifying MAC: %v", err)
		} else if !ok {
			return fmt.Sprintf("PUSH: MAC verification returned false")
		}
	}
	return ""
}

func genCryptoData(key *ssc.StrongSaltKey) (*cryptoData, error) {
	data := &cryptoData{}

	serializedKey, err := key.Serialize()
	if err != nil {
		return nil, err
	}
	data.Key = base64.URLEncoding.EncodeToString(serializedKey)

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
	serializedKey, err := base64.URLEncoding.DecodeString(reqData.Key)
	if err != nil {
		msg := fmt.Sprintf("PUSH: Error decoding base64 key string: %v", err)
		log.Printf(msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
	}
	key, err := ssc.DeserializeKey(serializedKey)
	if err != nil {
		msg := fmt.Sprintf("PUSH: error deserializing key: %v", err)
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
		Type string
	}
	err := json.NewDecoder(req.Body).Decode(&typeStruct)
	if err != nil {
		msg := fmt.Sprintf("PULL: Error decoding request json: %v", err)
		log.Printf(msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
	}

	keyType := ssc.TypeFromName(typeStruct.Type)
	if keyType == nil {
		msg := fmt.Sprintf("PULL: There is no key type named: %v", typeStruct.Type)
		log.Printf(msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
	}
	key, err := ssc.GenerateKey(keyType)
	if err != nil {
		msg := fmt.Sprintf("PULL: Error generating key of type %v: %v", typeStruct.Type, err)
		log.Printf(msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
	}

	resData, err := genCryptoData(key)
	if err != nil {
		msg := fmt.Sprintf("PULL: error generating data for response: %v", err)
		log.Printf(msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
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
