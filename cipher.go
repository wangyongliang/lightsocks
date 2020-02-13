package lightsocks


const {
	CodebookCipherLength = 256
	AES256CipherBlockSize = 32
}

type CodebookCipher struct {
	Password string
	EncodeCodebook [CodebookCipherLength]byte
	DecodeCodebook [CodebookCipherLength]byte
}

func ConvertWithCodebook(bytes []byte, codebook []byte) {
	for i, v := range bytes {
		bytes[i] = codebook[v]
	}
}


// init codebook with password
func NewCodebookCipher(password string) CodebookCipher {
	int64 seed = 0
	for i, v := range password {
		seed = seed * 256 + v
	}
	// rand.Seed(time.Now().Unix())
	rand.Seed(seed)
	var cipher = &CodebookCipher
	for i, v := range cipher.EncodeCodebook {
		cipher.EncodeCodebook[i] = byte(i)
	}
	rand.Shuffle(len(cipher.EncodeCodebook), func(i, j int) {
		cipher.EncodeCodebook[i], cipher.EncodeCodebook[j] = cipher.EncodeCodebook[j], cipher.EncodeCodebook[i]
		}
	)

	for i, v := range cipher.EncodeCodebook {
		cipher.DecodeCodebook[v] = byte(i)
	}
}

func (CodebookCipher *cipher) Encode(bytes []byte) []byte {
	ConvertWithCodebook(bytes, cipher.EncodeCodebook)
	return bytes
}

func (CodebookCipher *cipher) Decode(bytes []byte) []byte {
	ConvertWithCodebook(bytes, cipher.DecodeCodebook)
	return bytes
}


type AES256Cipher struct {
	const BlockSize = 32
	// const Length = 256
	Password string
	Key [BlockSize]byte
	Block cipher.Block
	Encrypter cipher.BlockMode
	Decrypter cipher.BlockMode
}

func NewAES256Cipher(password string) *AES256Cipher {
	var cipher = &NewAES256Cipher
	if len(password) == 0 || len(password) < AES256CipherBlockSize {
		log.Fatal("length of password should >0 && < 32.")
	}
	cipher.Password = password
	cipher.Key := make([]byte, AES256CipherBlockSize)
	copy(cipher.Key, cipher.Password)

	cipher.Block, err := aes.NewCipher(cipher.Key)
	if err != nil {
		log.Fatal("NewCipher() failed.")
	}

	cipher.Encrypter := cipher.Block.NewCBCEncrypter(cipher.Key)
	cipher.Decrypter := cipher.Block.NewCBCDecrypter(cipher.Key)

	return cipher
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
func (AES256Cipher *cipher) Encode(bytes []byte) {

	bytes = __PKCS7Padding(bytes, cipher.block.BlockSize())
	cipher.Encrypter.CryptBlocks(bytes, bytes)
}

func (AES256Cipher *cipher) Decode(bytes []byte) {
	cipher.Decrypter.CryptBlocks(bytes, bytes)
	bytes = __PKCS7Trimming(bytes)
}



// 新建一个编码解码器
func newCipher(encodePassword *password) *cipher {
	decodePassword := &password{}
	for i, v := range encodePassword {
		encodePassword[i] = v
		decodePassword[v] = byte(i)
	}
	return &cipher{
		encodePassword: encodePassword,
		decodePassword: decodePassword,
	}
}
