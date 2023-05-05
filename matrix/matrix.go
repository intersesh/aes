// Package matrix contains data structures to make reasoning through the AES
// paper a bit simpler on a high level, at the cost of some efficiency.
package matrix

import (
	"fmt"
)

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

// Vector is a row or column in a Matrix.
type Vector []byte

// String returns a padded hexadecimal representation of a Vector.
func (v Vector) String() string {
	return fmt.Sprintf("| %02x | %02x | %02x | %02x |", v[0], v[1], v[2], v[3])
}

// Matrix is a nice way to represent the state and other table-like data
// described in the AES paper.
type Matrix []Vector

// NewMatrix returns an empty matrix populated with data from the given byte slice.
// The matrix will have as many rows as is required to contain all given data.
// Data is inserted in a row-first fashion.
func NewMatrix(bytes []byte, columns int) Matrix {
	out := make(Matrix, 0, len(bytes)/columns)
	for i := 0; i < (len(bytes) / columns); i++ {
		out = append(out, bytes[i*columns:(i*columns)+columns])
	}
	return out
}

// EmptyMatrix returns a matrix initialised with empty Vectors.
func EmptyMatrix(columns, rows int) Matrix {
	out := make(Matrix, rows)
	for i := 0; i < rows; i++ {
		out[i] = make(Vector, columns)
	}

	return out
}

// String returns a padded hexadecimal representation of a Matrix.
func (m Matrix) String() string {
	hr := "-------------------------\n"
	out := "\n" + hr
	for _, row := range m {
		out += fmt.Sprintf("| %02x | %02x | %02x | %02x |\n", row[0], row[1], row[2], row[3])
	}
	out += hr

	return out
}

// Transpose returns a transposed copy of a Matrix.
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

// SetColumn replaces the column at the given index with the given Vector, in place.
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

// SetRow replaces the row at the given index with the given Vector, in place.
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
