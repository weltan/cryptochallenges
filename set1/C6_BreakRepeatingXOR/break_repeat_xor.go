package main

import (
	//"github.com/weltan/cryptochallenges/utils"
	"fmt"
	"log"
	"os"
)

const cipherFileName = "/Users/ken/code/src/github.com/weltan/cryptochallenges/set1/C6_BreakRepeatingXOR/6.txt"

func HammingDistance(a, b []byte) int {
	hammingCount := 0
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			hammingCount++
		}
	}
	return hammingCount
}

func StringHammingDistance(a, b string) int {
	aBytes := []byte(a)
	bBytes := []byte(b)
	return HammingDistance(aBytes, bBytes)
}

func main() {
	file, err := os.Open(cipherFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	a := "this is a test"
	b := "wokka wokka!!!"
	fmt.Println(StringHammingDistance(a, b))

	var c byte = 109
	var d byte = 219

	fmt.Println((c >> 6) ^ (d >> 6))
}
