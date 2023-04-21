package aes

import (
	"fmt"
	"math/bits"

	"github.com/ny0m/aes/matrix"
)

// Mod returns the remainder of the given arguments using division for the
// field GF(2⁸), as defined in the AES128 paper, FIPS-197 Section 4.2.
func Mod(dividend, divisor int) int {
	remainder := dividend

	for remainder != 0 && degree(remainder) >= degree(divisor) {
		distance := degree(remainder) - degree(divisor)
		shiftedDivisor := divisor << distance
		remainder ^= shiftedDivisor
	}

	return remainder
}

// degree returns the position of the most significant bit,
// i.e. the degree of a polynomial in the field GF(2⁸).
func degree(a int) int {
	if a == 0 {
		return -1
	}

	return bits.Len(uint(a))
}

func DotProduct(a, b matrix.Vector) byte {
	if len(a) != len(b) {
		panic(fmt.Sprintf("vector a has length '%d' and vector b has length of '%d'", len(a), len(b)))
	}

	var out byte
	for i := 0; i < len(a); i++ {
		out ^= Multiply(a[i], b[i])
	}

	return out
}

func Multiply(a, b byte) byte {
	reduction := byte(0) // Repeatedly matrix.XOR this with positive bits.
	intermediateXtime := a
	for i := 0; i < bits.Len(uint(b)); i++ {
		mask := byte(Exp2(i))
		isPositive := b&mask > 0

		if isPositive {
			reduction ^= intermediateXtime
		}

		intermediateXtime = Xtime(intermediateXtime)
	}
	return reduction
}

func Xtime(a byte) byte {
	mask := 0b10000000
	maskT := byte(mask)
	is7Set := a&maskT > 0

	temp := uint16(a << 1)

	if is7Set {
		temp ^= poly
	}

	outputMask := byte(0b11111111)

	return byte(temp) & outputMask
}

func Exp2(i int) int {
	return 1 << i
}
