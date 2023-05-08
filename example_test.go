package aes_test

import (
	"log"

	"github.com/ny0m/aes"
)

func Example() {
	// Generate a key from a collection of bytes.
	// For AES, key are either 16, 24, or 32 bytes long.
	// Hopefully it's easy to remember.
	key := aes.NewKey([]byte("ABSENTMINDEDNESS"))

	// Create a cipher with the key.
	// This can be used to encrypt messages.
	c := aes.NewCipher(key)

	// Create a 128-bit block from a message that we'd like to send.
	block := aes.NewBlock([]byte("a secret message"))

	// Finally, use the cipher to encrypt the block.
	out := c.Encrypt(block)

	// Et voila!
	log.Println(out)
}
