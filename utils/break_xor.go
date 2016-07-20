package utils

import (
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strconv"
)

var m map[byte]float64

func letterFrequency(lowercaseLetter byte, s []byte) float64 {
	uppercaseLetter := lowercaseLetter - 26
	occurrences := 0
	totalLength := len(s)
	for i := 0; i < totalLength; i++ {
		if s[i] == lowercaseLetter || s[i] == uppercaseLetter {
			occurrences++
		}
	}
	return float64(occurrences) / float64(totalLength)
}

func letterFreqProfile(s []byte) [91]float64 {
	var profile [91]float64
	for i := 65; i < 91; i++ {
		profile[i] = letterFrequency(byte(i), s)
	}
	return profile
}

func badCharsScore(s []byte) float64 {
	var score float64 = 0.0
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] > 126 {
			score += 0.05
		}
		if s[i] == 32 {
			score -= 0.5
		}
		if (s[i] > 64 && s[i] < 91) || (s[i] > 96 && s[i] < 123) {
			score -= 0.5
		}
	}
	return score
}

func englishScore(p [91]float64) float64 {
	score := 0.0

	m = make(map[byte]float64)

	m[65] = 8.167
	m[66] = 1.492
	m[67] = 2.782
	m[68] = 4.253
	m[69] = 12.702
	m[70] = 2.228
	m[71] = 2.015
	m[72] = 6.094
	m[73] = 6.966
	m[74] = 0.153
	m[75] = 0.772
	m[76] = 4.025
	m[77] = 2.406
	m[78] = 6.749
	m[79] = 7.507
	m[80] = 1.929
	m[81] = 0.095
	m[82] = 5.987
	m[83] = 6.327
	m[84] = 9.056
	m[85] = 2.758
	m[86] = 2.360
	m[87] = 2.361
	m[88] = 0.150
	m[89] = 1.974
	m[90] = 0.074

	for i := 65; i < 91; i++ {
		score += math.Abs(m[byte(i)] - p[i])
	}
	return score
}

var EnglishLetterFrequencies = map[string]float64{
	"a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702,
	"f": 2.228, "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153,
	"k": 0.772, "l": 4.025, "m": 2.406, "n": 6.749, "o": 7.507,
	"p": 1.929, "q": 0.095, "r": 5.987, "s": 6.327, "t": 9.056,
	"u": 2.758, "v": 2.360, "w": 2.361, "x": 0.150, "y": 1.974,
	"z": 0.074, " ": 13.0, // space is slightly more frequent than (e)
}

func EnglishScore(stringBytes []byte) float64 {
	var score float64
	for i := 0; i < len(stringBytes); i++ {
		score += EnglishLetterFrequencies[string(stringBytes[i])]
	}
	return score
}

type Result struct {
	Result []byte
	Score  float64
	Key    byte
}

type Results []Result

func (slice Results) Len() int {
	return len(slice)
}

func (slice Results) Less(i, j int) bool {
	return slice[i].Score > slice[j].Score
}

func (slice Results) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

// given an arbitrary cipher string that has been X'ORed with characters, find the key
func FindXOR(c string) ([]byte, float64, byte) {
	cipher, _ := hex.DecodeString(c)
	var bestTenResults = make(Results, 10)
	var key int
	for key = 0; key < 256; key++ {
		keyByte := byte(key)
		result := XORKeyByte(cipher, keyByte)

		//freqProfile := letterFreqProfile(result)
		//badCharsScore := badCharsScore(result)

		//keyScore := englishScore(freqProfile) + badCharsScore

		keyScore := EnglishScore(result)

		if bestTenResults[0].Score == 0.0 {
			bestTenResults[0] = Result{Result: result, Score: keyScore, Key: keyByte}
			sort.Sort(bestTenResults)
		} else if keyScore > bestTenResults[9].Score {
			bestTenResults[9] = Result{Result: result, Score: keyScore, Key: keyByte}
			sort.Sort(bestTenResults)
		}
	}
	return bestTenResults[0].Result, bestTenResults[0].Score, bestTenResults[0].Key
}

func FindXORBytes(cipher []byte) ([]byte, float64, byte) {
	var bestTenResults = make(Results, 10)
	var key int
	for key = 0; key < 256; key++ {
		keyByte := byte(key)
		result := XORKeyByte(cipher, keyByte)

		//freqProfile := letterFreqProfile(result)
		//badCharsScore := badCharsScore(result)

		//keyScore := englishScore(freqProfile) + badCharsScore

		keyScore := EnglishScore(result)

		if bestTenResults[0].Score == 0.0 {
			bestTenResults[0] = Result{Result: result, Score: keyScore, Key: keyByte}
			sort.Sort(bestTenResults)
		} else if keyScore > bestTenResults[9].Score {
			bestTenResults[9] = Result{Result: result, Score: keyScore, Key: keyByte}
			sort.Sort(bestTenResults)
		}
	}
	return bestTenResults[0].Result, bestTenResults[0].Score, bestTenResults[0].Key
}

func FindXORBytesTopResults(cipher []byte, topX int) Results {
	var bestTenResults = make(Results, 10)
	var key int
	for key = 0; key < 256; key++ {
		keyByte := byte(key)
		result := XORKeyByte(cipher, keyByte)

		//freqProfile := letterFreqProfile(result)
		//badCharsScore := badCharsScore(result)

		//keyScore := englishScore(freqProfile) + badCharsScore

		keyScore := EnglishScore(result)

		if bestTenResults[0].Score == 0.0 {
			bestTenResults[0] = Result{Result: result, Score: keyScore, Key: keyByte}
			sort.Sort(bestTenResults)
		} else if keyScore > bestTenResults[9].Score {
			bestTenResults[9] = Result{Result: result, Score: keyScore, Key: keyByte}
			sort.Sort(bestTenResults)
		}
	}
	return bestTenResults[0:topX]
}

func PrintByteArray(b []byte, s float64) {
	fmt.Printf("Result [%v]: %s\n\n", s, strconv.Quote(string(b)))
}
