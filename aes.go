package aes

import (
	"fmt"

	"github.com/ny0m/aes/matrix"
)

const (
	// numColumns is always set to 4 for AES,
	// although Rijndael supports a variable number of columns.
	// See 'Nb' parameter in FIPS-197 Section 2.2.
	numColumns = 4
)

// Cipher consists of a parsed key and its derived schedule.
// Depending on key size, will perform a different number of rounds during
// encryption and decryption.
type Cipher struct {
	schedule  []Word
	numRounds int
}

func NewCipher(key Key) Cipher {
	// In our implementation, Word is a 32-bit uint (which contains 4 bytes),
	// which means that we can just take the length of the key to figure out
	// how many words there are.
	wordsInKey := len(key)

	// How many rounds we do is always dependent on how large the key is.
	// Check 'Nr' parameter in FIPS-197 Section 2.2.
	numRounds := 6 + wordsInKey

	return Cipher{
		schedule:  expandKey(key, numRounds, wordsInKey, numColumns),
		numRounds: numRounds,
	}
}

// Block is just a byte array.
// AES is a 128-bit symmetric block cipher, which means that it takes 128 bits as input,
// and returns 128 bits output, irrespective of key size.
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

// Word is an array of 4 bytes represented as a single uint32.
type Word uint32

func (w Word) String() string {
	return matrix.NewVector(uint32(w)).String()
}

// NewWord converts a byte slice of length 4 to a 32-bit Word.
func NewWord(bytes []byte) Word {
	if l := len(bytes); l != 4 {
		panic(fmt.Sprintf("aes.NewWord: byte slice length must be of length 4; received %d; ", l))
	}

	return Word(uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3]))
}

// Words returns a slice of 32-bit words from a given byte slice.
// Panics if the byte slice is not a multiple of 4.
func Words(bytes []byte) []Word {
	l := len(bytes)

	out := make([]Word, l/4)
	for i := 0; i < len(bytes)/4; i++ {
		out[i] = NewWord(bytes[i*4 : i*4+4])
	}

	return out
}

// Encrypt implements the AES flavour of the Rijndael algo.
// See FIPS-197 Section 5.1.
func (c Cipher) Encrypt(block Block) Block {
	state := parse(block)

	// The zeroth round only consists of adding the round key.
	state = addRoundKey(state, c.schedule, 0)

	// The intermediate rounds consist of all four steps:
	// byte substitution, row shifting, column mixing, and adding the round key.
	for round := 1; round < c.numRounds; round++ {
		state = subBytes(state)
		state = shiftRows(state)
		state = mixColumns(state, mixColumnPolynomials)
		state = addRoundKey(state, c.schedule, round)
	}

	// The last round excludes column mixing.
	state = subBytes(state)
	state = shiftRows(state)
	state = addRoundKey(state, c.schedule, c.numRounds)

	return matrixBlock(state)
}

// Decrypt is an implementation of the InvCipher function.
// It's effectively the inverse of the Encrypt function;
// the steps are applied in reverse order.
// See FIPS-197 Section 5.3.
func (c Cipher) Decrypt(block Block) Block {
	state := parse(block)

	state = addRoundKey(state, c.schedule, c.numRounds)

	for round := c.numRounds - 1; round >= 1; round-- {
		state = shiftRowsInverse(state)
		state = subBytesInverse(state)
		state = addRoundKey(state, c.schedule, round)
		state = mixColumns(state, mixColumnPolynomialsInverse)
	}
	state = shiftRowsInverse(state)
	state = subBytesInverse(state)
	state = addRoundKey(state, c.schedule, 0)
	return matrixBlock(state)
}

// parse is just syntactic sugar to keep our Encrypt and Decrypt functions readable.
// We transpose the initial state matrix because the AES paper describes the state
// in a column-first fashion
// See FIPS-197 Section 3.4.
func parse(block Block) matrix.Matrix {
	return matrix.NewMatrix(block[:], 4).Transpose()
}

func addRoundKey(state matrix.Matrix, schedule []Word, round int) matrix.Matrix {
	numColumns := 4
	out := matrix.EmptyMatrix(4, 4)

	for i := 0; i < numColumns; i++ {
		stateColumn := matrix.ColumnVector(state, i)
		wordVector := matrix.NewVector(uint32(schedule[round*numColumns+i]))
		result := matrix.XOR(stateColumn, wordVector)
		out.SetColumn(result, i)
	}

	return out
}

func subBytes(state matrix.Matrix) matrix.Matrix {
	out := matrix.EmptyMatrix(4, 4)

	for row := range state {
		for col := range state[row] {
			out[row][col] = sbox[state[row][col]]
		}
	}

	return out
}

func subBytesInverse(state matrix.Matrix) matrix.Matrix {
	out := matrix.EmptyMatrix(4, 4)

	for row := range state {
		for col := range state[row] {
			out[row][col] = sboxInverse[state[row][col]]
		}
	}
	return out
}

func shiftRows(state matrix.Matrix) matrix.Matrix {
	out := matrix.EmptyMatrix(4, 4)
	for i := 0; i < 4; i++ {
		out[i] = append(append(matrix.Vector{}, state[i][i:]...), state[i][:i]...)
	}

	return out
}

func shiftRowsInverse(state matrix.Matrix) matrix.Matrix {
	out := matrix.EmptyMatrix(4, 4)
	for i := 0; i < 4; i++ {
		pivot := 4 - i
		out[i] = append(append(matrix.Vector{}, state[i][pivot:]...), state[i][:pivot]...)
	}
	return out
}

func mixColumns(state, polynomials matrix.Matrix) matrix.Matrix {
	out := matrix.EmptyMatrix(4, 4)
	for row := 0; row < len(state); row++ {
		for col := 0; col < len(state[row]); col++ {
			out[row][col] = DotProduct(matrix.RowVector(polynomials, row), matrix.ColumnVector(state, col))

			// Equivalent to:
			// p1, p2, p3, p4 := a.mixColumnPolynomials[i][0], a.mixColumnPolynomials[i][1], a.mixColumnPolynomials[i][2], a.mixColumnPolynomials[i][3]
			// s1, s2, s3, s4 := a.state[0][j], a.state[1][j], a.state[2][j], a.state[3][j]
			//
			// a.state[i][j] = Multiply(p1, s1) ^ Multiply(p2, s2) ^ Multiply(p3, s3) ^ Multiply(p4, s4)
		}
	}

	return out
}

// SubstituteWord applies the substitution algorithm from FIPS-197 Section 5.2.
func SubstituteWord(w Word) Word {
	var out Word

	// Words are always 4 bytes.
	for i := 1; i < 5; i++ {
		shift := 32 - 8*i
		index := w >> shift & 0xff
		substitution := Word(sbox[index]) << shift
		out |= substitution
	}

	return out
}

func matrixBlock(m matrix.Matrix) Block {
	var out Block
	for row := range m {
		for col := range m[row] {
			index := (row * 4) + col
			out[index] = m[col][row]
		}
	}

	return out
}

// RotateWord moves the most significant 8 bits of a word
// to the least significant.
func RotateWord(w Word) Word {
	return w<<8 | w>>24
}

// Rcon returns the round constant, which is a 4-bit polynomial represented
// as a power of two raised by the round number, mod poly.
//
// The result is shifted three bytes to the left, since these constants are
// always of the form x³.
func Rcon(round int) Word {
	return Word(Mod(Exp2(round), poly)) << 24
}

// poly is the irreducible polynomial for GF(2⁸),
// chosen for the AES128 implementation.
const poly = 1<<8 | 1<<4 | 1<<3 | 1<<1 | 1<<0 // x⁸ + x⁴ + x³ + x + 1
