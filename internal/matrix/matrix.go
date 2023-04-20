package matrix

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

type Vector []byte

func (v Vector) String() string {
	return fmt.Sprintf("| %-2x | %-2x | %-2x | %-2x |", v[0], v[1], v[2], v[3])
}

// NewVector splits an unsigned 32-bit integer into a 4-byte Vector.
func NewVector(n uint32) Vector {
	mask := byte(0xff)
	return Vector{
		byte(n >> 24),
		byte(n>>16) & mask,
		byte(n>>8) & mask,
		byte(n) & mask,
	}
}

type Matrix []Vector

func (m Matrix) String() string {
	hr := "-------------------------\n"
	out := "\n"
	out += hr
	for _, row := range m {
		out += fmt.Sprintf("| %-3x | %-3x | %-3x | %-3x |\n", row[0], row[1], row[2], row[3])
	}
	out += hr

	return out
}

func (m Matrix) Transpose() Matrix {
	out := make(Matrix, 0, len(m[0]))
	for i := 0; i < len(m); i++ {
		out = append(out, make(Vector, len(m)))
		for j := 0; j < len(m[0]); j++ {
			out[i][j] = m[j][i]
		}
	}

	return out
}

func (m Matrix) SetColumn(column Vector, index int) {
	size := len(m)
	if index > len(m[0]) {
		panic(fmt.Sprintf("column is %d, but matrix only has %d columns", index, len(m[0])))
	}

	if len(column) != size {
		panic(fmt.Sprintf("vector is of len %d, should be %d", len(column), size))
	}

	for i := 0; i < size; i++ {
		m[i][index] = column[i]
	}
}

func (m Matrix) SetRow(row Vector, index int) {
	size := len(m)
	if index > size {
		panic(fmt.Sprintf("row is %d, but matrix only has %d rows", row, size))
	}

	if len(row) != len(m[0]) {
		panic(fmt.Sprintf("vector is of len %d, should be %d", len(row), len(m[0])))
	}

	m[index] = row
}

func NewMatrix(slice []byte, columns int) Matrix {
	out := make(Matrix, 0, len(slice)/columns)
	for i := 0; i < (len(slice) / columns); i++ {
		out = append(out, slice[i*columns:(i*columns)+columns])
	}

	return out
}

func EmptyMatrix(columns, rows int) Matrix {
	out := make(Matrix, rows)
	for i := 0; i < rows; i++ {
		out[i] = make(Vector, columns)
	}

	return out
}

// ColumnVector returns the values that correspond to the column of a Matrix
// at the given index.
func ColumnVector(m Matrix, index int) Vector {
	columnLength := len(m)
	v := make(Vector, columnLength)

	for i := 0; i < columnLength; i++ {
		v[i] = m[i][index]
	}

	return v
}

// RowVector is  just syntactic sugar over indexing a Matrix.
func RowVector(m Matrix, index int) Vector {
	return m[index]
}

func Transpose(m Matrix, size int) Matrix {
	out := make(Matrix, size)

	for row := 0; row < size; row++ {
		for _, column := range m {
			out[row] = append(out[row], column[row])
		}
	}
	return out
}

// XOR repeatedly XORs the bytes of key with the bytes of message.
func XOR(a, b Vector) Vector {
	size := len(a)
	if len(b) != size {
		panic("XOR: vectors are not the same length")
	}

	out := make([]byte, size)
	for i, b := range b {
		out[i] = b ^ a[i%size]
	}

	return out
}

// BitwiseDistance finds the bit difference in the given byte arrays.
// Panics if len(a) != len(b).
func BitwiseDistance(a, b []byte) int {
	if len(a) != len(b) {
		panic("BitwiseDistance: inputs are of different lengths")
	}

	d := 0
	for i, v := range a {
		bits := fmt.Sprintf("%b", v^b[i])

		d += len(strings.Split(bits, "1")) - 1
	}

	return d
}

type result struct {
	distance           float32
	normalisedDistance float32
	keysize            int
}

// LikelyKeySize tries to guess the size of the key that was used to encrypt
// a string using a repeated-XOR cypher.
func LikelyKeySize(input []byte, start, end int) []result {
	var results []result
	for keysize := start; keysize < end; keysize++ {
		m := NewMatrix(input, keysize)
		var totalDistance int
		for i := 0; i < len(m)-1; i += 2 {
			key1 := m[i]
			key2 := m[i+1]
			totalDistance += BitwiseDistance(key1, key2)
		}
		averageDistance := float32(totalDistance) / float32(len(m))
		normalisedDistance := float32(averageDistance) / float32(keysize)

		results = append(results, result{
			distance:           averageDistance,
			normalisedDistance: normalisedDistance,
			keysize:            keysize,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].normalisedDistance < results[j].normalisedDistance
	})

	return results
}

type scored struct {
	key     byte
	message string
	score   float32
}

func HowEnglish(input string) float32 {
	score := 0

	for _, s := range input {
		if letters[s] {
			score++
		}
	}

	return float32(score) / float32(utf8.RuneCountInString(input))
}

func GuessSingleByteXOR(in []byte) byte {
	scores := make([]scored, 0)

	for key := byte(0); key < 255; key++ {
		potentialMessage := XOR([]byte{key}, in)

		score := HowEnglish(string(potentialMessage))
		scores = append(scores, scored{
			message: string(potentialMessage),
			score:   score,
			key:     key,
		})
	}

	sort.Slice(scores, func(i, j int) bool {
		return scores[i].score > scores[j].score
	})

	return scores[0].key
}

var letters = map[rune]bool{
	'a': true,
	'b': true,
	'c': true,
	'd': true,
	'e': true,
	'f': true,
	'g': true,
	'h': true,
	'i': true,
	'j': true,
	'k': true,
	'l': true,
	'm': true,
	'n': true,
	'o': true,
	'p': true,
	'q': true,
	'r': true,
	's': true,
	't': true,
	'u': true,
	'v': true,
	'w': true,
	'x': true,
	'y': true,
	'z': true,
	' ': true,
}

func Exp2(i int) int {
	return 1 << i
}
