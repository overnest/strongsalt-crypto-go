package strongsaltcrypto

import (
	"fmt"
	"io"

	. "github.com/overnest/strongsalt-crypto-go/interfaces"
)

var (
	ErrStreamClosed = fmt.Errorf("The stream is closed.")
)

//
// Encryptor
//

type Encryptor struct {
	key         KeyMidstream
	nonce       []byte
	plaintext   []byte
	ciphertext  []byte
	blockNum    int32
	closed      bool
	writeClosed bool
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
	if e.closed || e.writeClosed {
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
	if len(e.ciphertext) == 0 && e.writeClosed {
		return 0, io.EOF
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
	ciphertext = append(e.ciphertext, ciphertext...) // remaining ciphertext + encrypted

	e.Close()

	return ciphertext, nil
}

func (e *Encryptor) GetNonce() []byte {
	return e.nonce
}

func (e *Encryptor) CloseWrite() error {
	if e.closed {
		return ErrStreamClosed
	}

	ciphertext, err := e.key.EncryptIC(e.plaintext, e.nonce, e.blockNum)
	if err != nil {
		return err
	}

	e.ciphertext = append(e.ciphertext, ciphertext...)
	e.plaintext = nil
	e.blockNum += int32(len(ciphertext) / e.key.BlockSize())

	e.writeClosed = true

	return nil
}

func (e *Encryptor) Close() error {
	e.closed = true
	e.writeClosed = true
	e.ciphertext = nil
	e.plaintext = nil
	return nil
}

//
// Decryptor
//

type Decryptor struct {
	key         KeyMidstream
	nonce       []byte
	plaintext   []byte
	ciphertext  []byte
	blockNum    int32
	closed      bool
	writeClosed bool
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
	if e.closed || e.writeClosed {
		return n, ErrStreamClosed
	}
	if p == nil {
		return
	}
	n = len(p)
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
	}

	if len(p) == 0 {
		return
	}

	e.ciphertext = append(e.ciphertext, p...)

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
	if len(e.plaintext) == 0 && e.writeClosed {
		return 0, io.EOF
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
	plaintext = append(e.plaintext, plaintext...) // remaining plaintext + decrypted

	e.Close()

	return plaintext, nil
}

func (e *Decryptor) CloseWrite() error {
	plaintext, err := e.key.DecryptIC(e.ciphertext, e.nonce, e.blockNum)
	if err != nil {
		return err
	}

	e.plaintext = append(e.plaintext, plaintext...)
	e.ciphertext = nil
	e.blockNum += int32(len(plaintext) / e.key.BlockSize())

	e.writeClosed = true

	return nil
}

func (e *Decryptor) Close() error {
	e.closed = true
	e.writeClosed = true
	e.ciphertext = nil
	e.plaintext = nil
	return nil
}
