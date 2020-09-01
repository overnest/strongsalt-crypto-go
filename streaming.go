package strongsaltcrypto

import (
	"fmt"

	. "github.com/overnest/strongsalt-crypto-go/interfaces"
)

var (
	ErrStreamClosed = fmt.Errorf("The stream is closed.")
)

/*
Encryption:
SDK they will want a stream they can write to
When they write to the stream, it will be encrypted,
    and the ciphertext will be sent to a MAC and the server

SDK returns a Writer
    - write to it, send to crypto client, read from crypto client
        - crypto client encrypts full blocks, saves rest
        - read only returns full blocks as a consequence
        - if read anything, send to mac and server
    - at close, send remaining bytes to crypto client, read from crypto client
        - needs a readlast() method
        - sent to mac, and server
        - get final mac, send to server

Crypto Client:
    - write to it, save plaintext, encrypt full blocks (save rest)
    - read returns whatever ciphertext is contained, up to argument
	- readlast encrypts remaining plaintext,


Decryption:
SDK they will want a stream they can read from
The stream will be an intermediary between the server and the customer

SDK Reader:
    - Read ciphertext from server (until end or at least full blocks greater than requested num bytes)
    - IF SERVER EOF:
        - computer final MAC, raise ERROR if fails
    - write ciphertext to crypto client decryptor and mac
        - crypto client decrypts full blocks, saves rest
    - IF SERVER EOF:
        - readlast() from crypto client
    - ELSE:
        - read request num bytes plaintext from crypto client

Crypto Client Decryptor:
    - Write ciphertext to crypto client, decrypt full blocks, save plaintext and rest of ciphertext
    - Read returns requested number of plaintext bytes from the buffer
    - readlast() decrypts remaining ciphertext and returns plaintext
*/
//func (k *StrongSaltKey) EncryptStream() (*io.WriteCloser, error)
// Calls k.key.generateNonce(), then k.key.EncryptIC

//func (k *StrongSaltKey) DecryptStream(stream *io.ReadCloser, initialCount int32) (*io.ReadCloser, error)
// pulls Nonce from beginning of stream, then uses k.key.DecryptIC

type Encryptor struct {
	key        KeyMidstream
	nonce      []byte
	plaintext  []byte
	ciphertext []byte
	blockNum   int32
	closed     bool
}

func NewEncryptor(key KeyMidstream) (*Encryptor, error) {
	if key == nil {
		return nil, fmt.Errorf("Encryptor key cannot be nil.")
	}
	nonce, err := key.GenerateNonce()
	if err != nil {
		return nil, err
	}
	return &Encryptor{
		plaintext:  make([]byte, 0),
		ciphertext: make([]byte, 0),
		key:        key,
		nonce:      nonce,
	}, nil
}

func (e *Encryptor) Write(p []byte) (n int, err error) {
	if e.closed {
		return n, ErrStreamClosed
	}
	if p == nil || len(p) == 0 {
		return
	}
	e.plaintext = append(e.plaintext, p...)
	n = len(p)

	blockSize := e.key.BlockSize()
	ciphertextLen := (len(e.plaintext) / blockSize) * blockSize
	if ciphertextLen == 0 {
		return
	}

	readyPlaintext := e.plaintext[:ciphertextLen]

	ciphertext, err := e.key.EncryptIC(readyPlaintext, e.nonce, e.blockNum)
	if err != nil {
		return
	}

	e.ciphertext = append(e.ciphertext, ciphertext...)
	e.plaintext = e.plaintext[len(ciphertext):]
	e.blockNum += int32(len(ciphertext) / blockSize)

	return
}

func (e *Encryptor) Read(p []byte) (n int, err error) {
	if e.closed {
		return n, ErrStreamClosed
	}
	if len(e.ciphertext) > len(p) {
		n = len(p)
	} else {
		n = len(e.ciphertext)
	}
	copy(p, e.ciphertext[:n])
	e.ciphertext = e.ciphertext[n:]
	return
}

func (e *Encryptor) ReadLast() ([]byte, error) {
	if e.closed {
		return nil, ErrStreamClosed
	}

	ciphertext, err := e.key.EncryptIC(e.plaintext, e.nonce, e.blockNum)
	if err != nil {
		return nil, err
	}

	e.Close()

	return ciphertext, nil
}

func (e *Encryptor) Close() error {
	e.closed = true
	e.ciphertext = nil
	e.plaintext = nil
	return nil
}

type Decryptor struct {
	key        KeyMidstream
	nonce      []byte
	plaintext  []byte
	ciphertext []byte
	blockNum   int32
	closed     bool
}

func NewDecryptor(key KeyMidstream, ic int32) (*Decryptor, error) {
	if key == nil {
		return nil, fmt.Errorf("Decryptor key cannot be nil.")
	}
	return &Decryptor{
		plaintext:  make([]byte, 0),
		ciphertext: make([]byte, 0),
		key:        key,
		blockNum:   ic,
	}, nil
}

func (e *Decryptor) Write(p []byte) (n int, err error) {
	if e.closed {
		return n, ErrStreamClosed
	}

	nonceSize := e.key.NonceSize()
	if len(e.nonce) < nonceSize {
		diff := nonceSize - len(e.nonce)
		var pDiff int
		if len(p) < diff {
			pDiff = len(p)
		} else {
			pDiff = diff
		}
		e.nonce = append(e.nonce, p[:pDiff]...)
		p = p[pDiff:]
		n = pDiff
	}

	if p == nil || len(p) == 0 || len(e.nonce) < nonceSize {
		return
	}

	e.ciphertext = append(e.ciphertext, p...)
	n = len(p)

	blockSize := e.key.BlockSize()
	plaintextLen := (len(e.ciphertext) / blockSize) * blockSize
	if plaintextLen == 0 {
		return
	}

	readyCiphertext := e.ciphertext[:plaintextLen]

	plaintext, err := e.key.DecryptIC(readyCiphertext, e.nonce, e.blockNum)
	if err != nil {
		return
	}

	e.plaintext = append(e.plaintext, plaintext...)
	e.ciphertext = e.ciphertext[len(plaintext):]
	e.blockNum += int32(len(plaintext) / blockSize)

	return
}

func (e *Decryptor) Read(p []byte) (n int, err error) {
	if e.closed {
		return n, ErrStreamClosed
	}
	if len(e.plaintext) > len(p) {
		n = len(p)
	} else {
		n = len(e.plaintext)
	}
	copy(p, e.plaintext[:n])
	e.plaintext = e.plaintext[n:]
	return
}

func (e *Decryptor) ReadLast() ([]byte, error) {
	if e.closed {
		return nil, ErrStreamClosed
	}

	plaintext, err := e.key.DecryptIC(e.ciphertext, e.nonce, e.blockNum)
	if err != nil {
		return nil, err
	}

	e.Close()

	return plaintext, nil
}

func (e *Decryptor) Close() error {
	e.closed = true
	e.ciphertext = nil
	e.plaintext = nil
	return nil
}