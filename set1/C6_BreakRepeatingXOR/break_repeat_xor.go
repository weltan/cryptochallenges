package main

import (
	"encoding/base64"
	"fmt"
	"github.com/weltan/cryptochallenges/utils"
	"io/ioutil"
	"math"
	"sort"
)

const cipherFileName = "/Users/ken/code/src/github.com/weltan/cryptochallenges/set1/C6_BreakRepeatingXOR/6.txt"
const cipherFileNameWin = "C:/Users/Ken/Documents/code/src/github.com/weltan/cryptochallenges/set1/C6_BreakRepeatingXOR/6.txt"
const cipherFileNameWinTest = "C:/Users/Ken/Documents/code/src/github.com/weltan/cryptochallenges/set1/C6_BreakRepeatingXOR/test.txt"

type KeySize struct {
	keySize int
	score   float64
}
type KeySizes []KeySize

func (k KeySizes) Len() int {
	return len(k)
}

func (k KeySizes) Swap(i, j int) {
	k[i], k[j] = k[j], k[i]
}

func (k KeySizes) Less(i, j int) bool {
	return k[i].score < k[j].score
}

func partitionBlocks(buf []byte, blockSize int) [][]byte {
	var blocks [][]byte
	for block := 0; block < len(buf)/blockSize; block++ {
		blocks = append(blocks, buf[block*blockSize:block*blockSize+blockSize])
	}
	return blocks
}

func transposePartitionedBlocks(blocks [][]byte) [][]byte {
	var tBlocks [][]byte
	for i := 0; i < len(blocks[0]); i++ {
		var tBlock []byte
		for j := 0; j < len(blocks); j++ {
			tBlock = append(tBlock, blocks[j][i])
		}
		tBlocks = append(tBlocks, tBlock)
	}
	return tBlocks
}

func findLikelyKeySizes(buf []byte) []KeySize {
	keySizes := make(KeySizes, 41)
	for keySize := 2; keySize < 41; keySize++ {
		blocks := partitionBlocks(buf, keySize)
		hDist := 0
		for i := 0; i < len(blocks)-1; i++ {
			hDist += utils.HammingDistance(blocks[i], blocks[i+1])
		}
		avgDist := hDist / len(blocks)
		normalized := float64(avgDist) / float64(keySize)
		keySizes[keySize] = KeySize{keySize: keySize, score: normalized}
	}
	sort.Sort(keySizes)
	return keySizes[2:]
}

func main() {
	base64Buf, _ := ioutil.ReadFile(cipherFileNameWin)
	buf, _ := base64.StdEncoding.DecodeString(string(base64Buf))

	keySizes := findLikelyKeySizes(buf)

	var highScore float64
	highScoreText := ""
	var highScoreKey []byte

	// for each key size, partition, transpose and find likely XOR key
	for _, keySize := range keySizes[0:3] {
		fmt.Println("------------------------------------")
		fmt.Println("Currently looking at keySize ", keySize.keySize)
		fmt.Println("------------------------------------")

		// break into blocks, then transpose
		blocks := partitionBlocks(buf, keySize.keySize)
		transposedBlocks := transposePartitionedBlocks(blocks)

		// find the top single-character byte that produce the best scores once XOR'ed
		var likelyKeys [][]byte
		for i := 0; i < len(transposedBlocks); i++ {
			topXResults := 1
			var results []utils.Result = utils.FindXORBytesTopResults(transposedBlocks[i], topXResults)
			var ks []byte
			for j := 0; j < len(results); j++ {
				ks = append(ks, results[j].Key)
			}
			likelyKeys = append(likelyKeys, ks)
		}

		// iterate through all combinations of the likely keys, using an arbitrary base system.
		// pretty cool, but since topXResults = 1, this doesn't do anything really.
		// builds a key
		for i := 0; i < int(math.Pow(float64(len(likelyKeys[0])), float64(len(likelyKeys)))); i++ {
			var key []byte
			k := 0
			prevBase := 0
			for j := len(likelyKeys) - 1; j > -1; j-- {
				// calculate jth index
				base := int(math.Pow(float64(len(likelyKeys[0])), float64(j)))

				ith := (i - prevBase) / base
				prevBase += ith * base
				key = append(key, likelyKeys[k][ith])
				k++
			}

			resultingDecryptedBytes := utils.XORRepeatingKey(buf, key)
			score := utils.EnglishScore(resultingDecryptedBytes)
			if score > highScore {
				highScoreKey = key
				highScore = score
				highScoreText = string(resultingDecryptedBytes)
				fmt.Println("new high score!:", string(resultingDecryptedBytes[0:15]))
			}
		}
	}
	fmt.Println("output: ", highScoreText)
	fmt.Println("key:", highScoreKey)
	fmt.Print("keySize:", len(highScoreKey))
}
