package matrix

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

type Numeric interface {
	uint | uint8 | uint16 | uint32 | uint64 |
		int | int8 | int16 | int32 | int64
}
type Vector[T Numeric] []T

func (v Vector[T]) String() string {
	return fmt.Sprintf("| %-2x | %-2x | %-2x | %-2x |", v[0], v[1], v[2], v[3])
}

type Matrix[T Numeric] []Vector[T]

func (m Matrix[T]) String() string {
	hr := "-------------------------\n"
	out := "\n"
	out += hr
	for _, row := range m {
		out += fmt.Sprintf("| %-3x | %-3x | %-3x | %-3x |\n", row[0], row[1], row[2], row[3])
	}
	out += hr

	return out
}

func (m Matrix[T]) Transpose() Matrix[T] {
	out := make(Matrix[T], 0, len(m[0]))
	for i := 0; i < len(m); i++ {
		out = append(out, make(Vector[T], len(m)))
		for j := 0; j < len(m[0]); j++ {
			out[i][j] = m[j][i]
		}
	}

	return out
}

func (m Matrix[T]) SetColumn(column Vector[T], index int) {
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

func (m Matrix[T]) SetRow(row Vector[T], index int) {
	size := len(m)
	if index > size {
		panic(fmt.Sprintf("row is %d, but matrix only has %d rows", row, size))
	}

	if len(row) != len(m[0]) {
		panic(fmt.Sprintf("vector is of len %d, should be %d", len(row), len(m[0])))
	}

	m[index] = row
}

func NewMatrix[T Numeric](slice []T, columns int) Matrix[T] {
	out := make(Matrix[T], 0, len(slice)/columns)
	for i := 0; i < (len(slice) / columns); i++ {
		out = append(out, slice[i*columns:(i*columns)+columns])
	}

	return out
}

func EmptyMatrix[T Numeric](columns, rows int) Matrix[T] {
	out := make(Matrix[T], rows)
	for i := 0; i < rows; i++ {
		out[i] = make(Vector[T], columns)
	}

	return out
}

// ColumnVector returns the values that correspond to the column of a Matrix
// at the given index.
func ColumnVector[T Numeric](m Matrix[T], index int) Vector[T] {
	columnLength := len(m)
	v := make(Vector[T], columnLength)

	for i := 0; i < columnLength; i++ {
		v[i] = m[i][index]
	}

	return v
}

// RowVector is  just syntactic sugar over indexing a Matrix.
func RowVector[T Numeric](m Matrix[T], index int) Vector[T] {
	return m[index]
}

func Transpose[T Numeric](m Matrix[T], size int) Matrix[T] {
	out := make(Matrix[T], size)

	for row := 0; row < size; row++ {
		for _, column := range m {
			out[row] = append(out[row], column[row])
		}
	}
	return out
}

// XOR repeatedly XORs the bytes of key with the bytes of message.
func XOR[T Numeric](a, b Vector[T]) Vector[T] {
	size := len(a)
	if len(b) != size {
		panic("XOR: vectors are not the same length")
	}

	out := make([]T, size)
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
