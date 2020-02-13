package lightsocks

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"log"
	"math/rand"
)

const (
	CodebookCipherLength  = 256
	AES256CipherBlockSize = 16
)

type Cipher interface {
	Encode([]byte) []byte
	Decode([]byte) []byte
}

type CodebookCipher struct {
	Password       string
	EncodeCodebook [CodebookCipherLength]byte
	DecodeCodebook [CodebookCipherLength]byte
}

func ConvertWithCodebook(bytes []byte, codebook [CodebookCipherLength]byte) {
	for i, v := range bytes {
		bytes[i] = codebook[v]
	}
}

//func ValidatePerm(perm []byte) {
//for i, v := range perm {
//if i == int
//}
//}

// init codebook with password
func NewCodebookCipher(password string) *CodebookCipher {
	seed := int64(0)
	//int64 seed = 0
	for _, v := range password {
		seed = seed*256 + int64(v)
	}
	// rand.Seed(time.Now().Unix())
	rand.Seed(seed)
	cipher := &CodebookCipher{}
	for i, _ := range cipher.EncodeCodebook {
		cipher.EncodeCodebook[i] = byte(i)
	}
	rand.Shuffle(len(cipher.EncodeCodebook), func(i, j int) {
		cipher.EncodeCodebook[i], cipher.EncodeCodebook[j] = cipher.EncodeCodebook[j], cipher.EncodeCodebook[i]
	})

	for i, v := range cipher.EncodeCodebook {
		cipher.DecodeCodebook[v] = byte(i)
	}
	return cipher
}

func (cipher *CodebookCipher) Encode(bytes []byte) []byte {
	ConvertWithCodebook(bytes, cipher.EncodeCodebook)
	return bytes
}

func (cipher *CodebookCipher) Decode(bytes []byte) []byte {
	ConvertWithCodebook(bytes, cipher.DecodeCodebook)
	return bytes
}

type AES256Cipher struct {
	Password  string
	Key       []byte
	Block     cipher.Block
	Encrypter cipher.BlockMode
	Decrypter cipher.BlockMode
}

func NewAES256Cipher(password string) *AES256Cipher {
	this := &AES256Cipher{}
	this.Key = make([]byte, AES256CipherBlockSize)
	if len(password) == 0 || len(password) > AES256CipherBlockSize {
		log.Fatal("length of password should >0 && < 32.")
	}
	this.Password = password
	for i, v := range password {
		this.Key[i] = byte(v)
	}
	//cipher.Key = make([]byte, AES256CipherBlockSize)
	//copy(cipher.Key, []byte(cipher.Password))

	block, err := aes.NewCipher(this.Key)
	if err != nil {
		log.Fatal("NewCipher() failed.")
	}
	this.Block = block
	this.Encrypter = cipher.NewCBCEncrypter(this.Block, this.Key)
	this.Decrypter = cipher.NewCBCDecrypter(this.Block, this.Key)
	return this
}

func __PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func __PKCS7Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

//---------------DES加密  解密--------------------
func (cipher *AES256Cipher) Encode(bytes []byte) []byte {

	bytes = __PKCS7Padding(bytes, cipher.Block.BlockSize())
	cipher.Encrypter.CryptBlocks(bytes, bytes)
	return bytes
}

func (cipher *AES256Cipher) Decode(bytes []byte) []byte {
	cipher.Decrypter.CryptBlocks(bytes, bytes)
	bytes = __PKCS7Trimming(bytes)
	return bytes
}

func NewCipher(mode, password string) (Cipher, error) {
	if mode == "codebook" {
		return NewCodebookCipher(password), nil
	}
	if mode == "aes" {
		return NewAES256Cipher(password), nil
	}
	return nil, errors.New("invalid mode")
}
