package lightsocks

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
)

const (
	MB = 1024 * 1024
)

func NewRandomBytes(length int) []byte {
	if length <= 0 {
		length = rand.Intn(1024)
	}
	bytes := make([]byte, length)
	rand.Read(bytes)
	return bytes
}

func PrintBytes(name string, bytes []byte) {
	fmt.Println("---" + name + "---")
	for _, v := range bytes {
		fmt.Println(int32(v))
	}
}

func TestCodebookCipher(t *testing.T) {
	password := "lightsocks"

	cipher := NewCodebookCipher(password)

	bytes := NewRandomBytes(10)
	start := make([]byte, len(bytes))
	copy(start, bytes)
	//PrintBytes("bytes", bytes)

	encode := cipher.Encode(bytes)
	//PrintBytes("encode", encode)
	//PrintBytes("bytes", bytes)
	if reflect.DeepEqual(encode, start) {
		t.Error("invalid encoder.")
	}

	decode := cipher.Decode(encode)
	//PrintBytes("decode", decode)

	if !reflect.DeepEqual(decode, start) {
		t.Error("invalid decoder.")
	}

	copy(bytes, start)
	other, err := NewCipher("codebook", password)
	if err != nil {
		t.Error(err)
	}
	decode = other.Decode(cipher.Encode(bytes))
	if !reflect.DeepEqual(decode, start) {
		t.Error("invalid decoder.")
	}
	//PrintBytes("decode", decode)
}

func TestAESCBC256Cipher(t *testing.T) {
	password := "lightsocks"

	cipher := NewAES256Cipher(password)

	bytes := NewRandomBytes(10)
	start := make([]byte, len(bytes))
	copy(start, bytes)
	//PrintBytes("bytes", bytes)

	encode := cipher.Encode(bytes)
	if reflect.DeepEqual(encode, start) {
		t.Error("invalid encoder.")
	}
	//PrintBytes("encode", encode)
	//PrintBytes("bytes", bytes)

	decode := cipher.Decode(encode)
	//PrintBytes("decode", decode)

	if !reflect.DeepEqual(decode, bytes) {
		t.Error("invalid decoder.")
	}

	cipher = NewAES256Cipher(password)
	copy(bytes, start)
	encode = cipher.Decode(cipher.Encode(bytes))

	if !reflect.DeepEqual(decode, bytes) {
		t.Error("invalid decoder.")
	}

}
