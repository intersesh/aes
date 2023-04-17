package aes

import (
	"fmt"
	"math/bits"

	"github.com/ny0m/aes/internal/matrix"
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

func DotProduct[T matrix.Numeric](a, b matrix.Vector[T]) T {
	if len(a) != len(b) {
		panic(fmt.Sprintf("vector a has length '%d' and vector b has length of '%d'", len(a), len(b)))
	}
	var out T
	for i := 0; i < len(a); i++ {
		out ^= Multiply(a[i], b[i])
	}

	return out
}

func Multiply[T matrix.Numeric](a, b T) T {
	reduction := T(0) // Repeatedly matrix.XOR this with positive bits.
	intermediateXtime := a
	for i := 0; i < bits.Len(uint(b)); i++ {
		mask := T(matrix.Exp2(i))
		isPositive := b&mask > 0

		// log.Printf("index: %d, mask: %b (%d), isPositive? %t, round: %d intermediate: %x", i, mask, mask, isPositive, i, intermediateXtime)
		if isPositive {
			reduction ^= intermediateXtime
		}

		intermediateXtime = Xtime(intermediateXtime)
	}
	return reduction
}

func Xtime[T matrix.Numeric](a T) T {
	mask := 0b10000000
	maskT := T(mask)
	is7Set := a&maskT > 0

	a = a << 1

	if is7Set {
		a ^= poly
	}

	outputMask := 0b11111111
	outputMaskT := T(outputMask)

	return a & outputMaskT
}
