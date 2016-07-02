package main

import (
	"github.com/weltan/cryptochallenges/utils"
	//"encoding/hex"
	//"unicode/utf8"
	"strings"
	//"strconv"
	"fmt"
	"math"
)

const cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

var m map[byte]float64

func letterFrequency(lowercaseLetter byte, s []byte) (float64) {
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

func letterFreqProfile (s []byte) ([91]float64){
	var profile [91]float64
	for i := 65; i < 91; i++ {
		profile[i] = letterFrequency(byte(i), s) 
	}
	return profile
}


func englishScore(p [91] float64) float64 {
	score := 0.0
	
	m = make(map[byte]float64)
	 
	m[65] = 0.0816
	m[66] = 0.0149
	m[67] = 0.0278
	m[68] = 0.0425
	m[69] = 0.1270
	m[70] = 0.0222
	m[71] = 0.0201
	m[72] = 0.0609
	m[73] = 0.0696
	m[74] = 0.0015
	m[75] = 0.0077
	m[76] = 0.0402
	m[77] = 0.0240
	m[78] = 0.0674
	m[79] = 0.0750
	m[80] = 0.0192
	m[81] = 0.0009
	m[82] = 0.0598
	m[83] = 0.0632
	m[84] = 0.0905
	m[85] = 0.0275
	m[86] = 0.0097
	m[87] = 0.0236
	m[88] = 0.001
	m[89] = 0.0197
	m[90] = 0.0007

	for i := 65; i < 91; i++ {
		score += math.Abs(m[byte(i)] - p[i]) 
	}
	return score
}

func main() {
	score := 1000.0
	var bestResult []byte 
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			key := utils.ItoHexString(i) + utils.ItoHexString(j)
			keyString := strings.Repeat(key, len(cipher) / 2)
			
			result, err := utils.HexXOR(cipher, keyString)
			
			
			freqProfile := letterFreqProfile(result)

			keyScore := englishScore(freqProfile)

			if keyScore < score {
				score = keyScore
				bestResult = result
			}
			
			if err != nil {
				fmt.Printf("%v", err)
			} else {
				if letterFrequency(101, result) > (0.1270 - 0.10) {
					//fmt.Println(keyScore)
					//fmt.Printf(">>>>>%s<<<<<\n\n", result)
				}
			}
		}
	}
	fmt.Printf("Best result: %s\n", bestResult) 
	fmt.Printf("Best score: %v\n", score) 
}