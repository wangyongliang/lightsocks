package lightsocks

import (
	"math/rand"
	"reflect"
	"testing"
)

const (
	MB = 1024 * 1024
)

func NewRandomBytes(length int) []byte{
	if length <= 0 {
		length = rand.intn(1024)
	}
	bytes := make([]byte, length)
	rand.Read(bytes)
	return bytes
}

// 测试 cipher 加密解密
func TestCodebookCipher(t *testing.T) {
	password := 'lightsocks'

	cipher := NewCodebookCipher(password)

	bytes := NewRandomBytes(10)

	encode := make([]byte, len(bytes))
	copy(encode, bytes)
	cipher.Encode(encode)

	decode :=make([]byte, len(encode))
	copy(decode, encode)
	cipher.Decode(decode)

	if !reflect.DeepEqual(decode, bytes) {
		t.Error("解码编码数据后无法还原数据，数据不对应")
	}
}

// func BenchmarkEncode(b *testing.B) {
// 	password := RandPassword()
// 	p, _ := parsePassword(password)
// 	cipher := newCipher(p)
// 	bs := make([]byte, MB)
// 	b.ResetTimer()
// 	rand.Read(bs)
// 	cipher.encode(bs)
// }

// func BenchmarkDecode(b *testing.B) {
// 	password := RandPassword()
// 	p, _ := parsePassword(password)
// 	cipher := newCipher(p)
// 	bs := make([]byte, MB)
// 	b.ResetTimer()
// 	rand.Read(bs)
// 	cipher.decode(bs)
// }
