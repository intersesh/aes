// Package blockcipher keeps things simple by only allowing a 128-bit block size,
// irrespective of key size.
package blockcipher

import "fmt"

// Block is just a byte array.
type Block [16]byte

// NewBlock returns a block that contains the given bytes,
// padded if len(bytes) < 16.
func NewBlock(bytes []byte) Block {
	if len(bytes) > 16 {
		panic("blocks cannot be larger than 16 bytes")
	}

	var block Block

	for i := 0; i < len(bytes); i++ {
		block[i] = bytes[i]
	}

	return block
}

// String returns a hexadecimal representation of each byte in the block.
func (b Block) String() string {
	return fmt.Sprintf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}
