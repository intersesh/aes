package blockcipher

type Cipher interface {
	Encrypt(block Block) Block
	Decrypt(block Block) Block
}
