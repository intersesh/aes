package aes

import (
	"fmt"

	"github.com/ny0m/aes/internal/matrix"
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
	key       Key
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
		key:       key,
		schedule:  expandKey(key, numRounds, wordsInKey, numColumns),
		numRounds: numRounds,
	}
}

// Block is just a byte array.
// AES is a 128-bit symmetric block cipher, which means that it takes 128 bits as input,
// and returns 128 bits of encrypted output (and vice-versa during decryption).
type Block [16]byte

func (b Block) String() string {
	return string(b[:])
}

// Word is an array of 4 bytes represented as a single uint32.
type Word uint32

// String returns a Word as four hex numbers.
func (w Word) String() string {
	return fmt.Sprintf("%x %x %x %x", w.Byte(0), w.Byte(1), w.Byte(2), w.Byte(3))
}

// Vector returns a Word as a four-byte Vector.
func (w Word) Vector() matrix.Vector[byte] {
	mask := byte(0xff)
	return matrix.Vector[byte]{
		byte(w >> 24),
		byte(w>>16) & mask,
		byte(w>>8) & mask,
		byte(w) & mask,
	}
}

// Byte returns a single byte from a Word.
func (w Word) Byte(i int) byte {
	shift := 32 - 8*(i+1)
	return uint8(w >> shift & 0b1111_1111)
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

func Words(bytes []byte) []Word {
	l := len(bytes)

	key := make([]Word, l/4)

	for i := 0; i < len(bytes)/4; i++ {
		word := Word(uint32(bytes[4*i])<<24 | uint32(bytes[4*i+1])<<16 | uint32(bytes[4*i+2])<<8 | uint32(bytes[4*i+3]))
		key[i] = word
	}

	return key
}

func parse(block Block) matrix.Matrix[byte] {
	out := matrix.EmptyMatrix[byte](4, 4)
	for r := 0; r < 4; r++ {
		for c := 0; c < 4; c++ {
			out[r][c] = block[r+(4*c)]
		}
	}

	return out
}

func addRoundKey(state matrix.Matrix[byte], schedule []Word, round int) matrix.Matrix[byte] {
	numColumns := 4
	out := matrix.EmptyMatrix[byte](4, 4)

	for i := 0; i < numColumns; i++ {
		stateColumn := matrix.ColumnVector(state, i)
		wordVector := schedule[round*numColumns+i].Vector()
		result := matrix.XOR(stateColumn, wordVector)
		out.SetColumn(result, i)
	}

	return out
}

func subBytes(state matrix.Matrix[byte]) matrix.Matrix[byte] {
	out := matrix.EmptyMatrix[byte](4, 4)

	for row := range state {
		for col := range state[row] {
			out[row][col] = sbox[state[row][col]]
		}
	}

	return out
}

func subBytesInverse(state matrix.Matrix[byte]) matrix.Matrix[byte] {
	out := matrix.EmptyMatrix[byte](4, 4)

	for row := range state {
		for col := range state[row] {
			out[row][col] = sboxInverse[state[row][col]]
		}
	}
	return out
}

func shiftRows(state matrix.Matrix[byte]) matrix.Matrix[byte] {
	out := matrix.EmptyMatrix[byte](4, 4)
	for i := 0; i < 4; i++ {
		out[i] = append(append(matrix.Vector[byte]{}, state[i][i:]...), state[i][:i]...)
	}

	return out
}

func shiftRowsInverse(state matrix.Matrix[byte]) matrix.Matrix[byte] {
	out := matrix.EmptyMatrix[byte](4, 4)
	for i := 0; i < 4; i++ {
		pivot := 4 - i
		out[i] = append(append(matrix.Vector[byte]{}, state[i][pivot:]...), state[i][:pivot]...)
	}
	return out
}

func mixColumns[T matrix.Numeric](state, polynomials matrix.Matrix[T]) matrix.Matrix[T] {
	out := matrix.EmptyMatrix[T](4, 4)
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

// SubstituteWord applies the substitution algorith from FIPS-197 Section 5.2.
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

func matrixBlock(m matrix.Matrix[byte]) Block {
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
	return Word(Mod(matrix.Exp2(round), poly)) << 24
}

// poly is the irreducible polynomial for GF(2⁸),
// chosen for the AES128 implementation.
const poly = 1<<8 | 1<<4 | 1<<3 | 1<<1 | 1<<0 // x⁸ + x⁴ + x³ + x + 1
