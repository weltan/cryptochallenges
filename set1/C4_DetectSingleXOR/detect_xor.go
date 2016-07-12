package main

import (
	"bufio"
	"github.com/weltan/cryptochallenges/utils"
	"log"
	"os"
)

const cipherFile = "/Users/ken/code/src/github.com/weltan/cryptochallenges/set1/C4_DetectSingleXOR/4.txt"

func main() {
	file, err := os.Open(cipherFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lowScore := 1000.0
	var bestResult []byte
	for scanner.Scan() {
		cipher := scanner.Text()
		var result, score = utils.FindXOR(cipher)
		if score < lowScore {
			bestResult = result
			lowScore = score
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	utils.PrintByteArray(bestResult, lowScore)
}
