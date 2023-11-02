package main

import (
	"flag"
	"io"
	"log"
	"os"

	"github.com/intersesh/crypto/aes"
	"github.com/intersesh/crypto/blockcipher"
)

func main() {
	flag.Parse()

	// Make sure the key you use is always 16 bytes long.
	keyStr := os.Getenv("AES_KEY")

	var (
		key    = aes.NewKey([]byte(keyStr))
		cipher = aes.NewCipher(key)

		op func(block blockcipher.Block) blockcipher.Block
	)

	switch a := flag.Arg(0); {
	case a == "encrypt":
		op = cipher.Encrypt
	case a == "decrypt":
		op = cipher.Decrypt
	default:
		log.Fatal("invalid op: ", a)
	}

	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal("error reading from stdin: ", err)
	}

	for i, j := 0, 16; i <= len(in); i, j = i+16, j+16 {
		// For the last block, make sure we don't try to index past the end of the input.
		if j > len(in) {
			j = len(in)
		}

		// Since AES is a block cipher,
		// we have to always process one exact block worth of bytes at a time.
		block := blockcipher.Block(in[i:j])

		b := op(block)
		if _, err := os.Stdout.Write(b[:]); err != nil {
			log.Fatal("failed to write to stdout: ", err)
		}
	}

}
