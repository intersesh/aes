package aes

import "fmt"

// Key is a group of 32-bit words that is used to generate a key schedule,
// which is in turn used to encrypt the state during successive rounds.
type Key []Word

// NewKey returns
func NewKey(bytes []byte) []Word {
	l := len(bytes)
	switch l {
	default:
		panic(fmt.Sprintf("wrong key length: %d", l))
	case 16, 24, 32:
		break
	}

	return Words(bytes)
}

func expandKey(key Key, numRounds, wordsInKey, numColumns int) []Word {
	var (
		out = make([]Word, numColumns*(numRounds+1))
		i   int
	)

	// The first n words in the schedule are just the first n words of the key.
	for ; i < wordsInKey; i++ {
		out[i] = key[i]
	}

	for i = wordsInKey; i < numColumns*(numRounds+1); i++ {
		word := out[i-1]
		if i%wordsInKey == 0 {
			word = SubstituteWord(RotateWord(word)) ^ Rcon(i/wordsInKey-1)
		} else if numColumns > 6 && i%numColumns == 4 {
			word = SubstituteWord(word)
		}
		out[i] = out[i-wordsInKey] ^ word
	}

	return out
}
