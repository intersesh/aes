package blockcipher

import (
	"crypto/rand"
	"encoding/binary"
	"log"
)

type Mode interface {
	Encrypt([]byte) []byte
	Decrypt([]byte) []byte
}

func NewECBMode(cipher Cipher) Mode {
	return &ecb{
		cipher: cipher,
	}
}

type ecb struct {
	cipher Cipher
}

func (e *ecb) Encrypt(bytes []byte) []byte {
	return doECB(e.cipher.Encrypt, bytes)
}
func (e *ecb) Decrypt(bytes []byte) []byte {
	return doECB(e.cipher.Decrypt, bytes)
}

func doECB(crypt func(Block) Block, bytes []byte) []byte {
	blocks := Blockify(bytes, 16)
	var out []byte

	for _, b := range blocks {
		block := crypt(b)
		out = append(out, block[:]...)
	}

	return out
}

func NewCBCMode(cipher Cipher, iv Block) Mode {
	return &cbc{
		iv:     iv,
		cipher: cipher,
	}
}

type cbc struct {
	iv     Block
	cipher Cipher
}

func (c *cbc) Encrypt(bytes []byte) []byte {
	blocks := Blockify(bytes, 16)
	var out []byte
	prevBlock := c.iv

	for _, b := range blocks {
		encrypted := c.cipher.Encrypt(Block(XOR(b[:], prevBlock[:])))
		prevBlock = encrypted
		out = append(out, encrypted[:]...)
	}

	return out
}
func (c *cbc) Decrypt(bytes []byte) []byte {
	blocks := Blockify(bytes, 16)
	var out []byte
	prevBlock := c.iv

	for _, b := range blocks {
		block := c.cipher.Decrypt(b)
		decrypted := XOR(block[:], prevBlock[:])
		prevBlock = b
		out = append(out, decrypted[:]...)
	}

	return out
}

func NewCTRMode(cipher Cipher) Mode {
	return &ctr{
		cipher: cipher,
	}
}

type ctr struct {
	nonce  int
	cipher Cipher
}

func (c *ctr) Encrypt(bytes []byte) []byte {
	blocks := Blockify(bytes, 16)
	var out []byte
	for _, b := range blocks {
		// i = 0
		nonce := make([]byte, 0, 16)
		// create byte array with nonce value
		nonce = append(nonce, LittleEndian(0, 8)...)
		// nonce = append(nonce, LittleEndian(uint64(c.nonce), 8)...)
		nonce = append(nonce, LittleEndian(uint64(0), 8)...)

		// encrypt nonce array with cipher to get keystream
		keystream := c.cipher.Encrypt(Block(nonce))

		// xor keystream with plaintext block to get ciphertext
		encrypted := make([]byte, 16)
		for i := 0; i < 16; i++ {
			encrypted[i] = keystream[i] ^ b[i]
		}

		out = append(out, encrypted...)
		c.nonce++
	}

	return out
}

func (c *ctr) Decrypt(bytes []byte) []byte {
	return c.Encrypt(bytes)
}

// XOR repeatedly XORs the bytes of key with the bytes of message.
func XOR(a, b []byte) []byte {
	size := len(a)
	if len(b) != size {
		panic("XOR: inputs are not the same length")
	}

	out := make([]byte, size)
	for i, b := range b {
		out[i] = b ^ a[i%size]
	}

	return out
}

func PadBytes(bytes []byte, length int) []byte {
	pad := byte(length - len(bytes))
	rounds := length - len(bytes)
	for i := 0; i < rounds; i++ {
		bytes = append(bytes, pad)
	}

	return bytes
}

func Blockify(bytes []byte, size int) []Block {
	if len(bytes)%size > 0 {
		bytes = PadBytes(bytes, len(bytes)/size+1)
	}

	block := make([]byte, size)
	var out []Block
	for i := range bytes {
		if i%16 == 0 && i > 0 {
			out = append(out, Block(block))
			block = make([]byte, size)
		}

		block[i%16] = bytes[i]
	}
	out = append(out, Block(block))

	return out
}

func LittleEndian(i uint64, wordLen int) []byte {
	bs := make([]byte, wordLen)
	binary.LittleEndian.PutUint64(bs, i)
	return bs
}

func RandomBytes(len int) []byte {
	key := make([]byte, len)
	if _, err := rand.Read(key); err != nil {
		log.Panicf("RandomBytes: %s", err)
	}

	return key
}
