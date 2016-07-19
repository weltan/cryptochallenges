package main

import (
	"encoding/base64"
	"fmt"
	"github.com/weltan/cryptochallenges/utils"
	"io/ioutil"
	"sort"
)

const cipherFileName = "/Users/ken/code/src/github.com/weltan/cryptochallenges/set1/C6_BreakRepeatingXOR/6.txt"

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

func main() {
	base64Buf, _ := ioutil.ReadFile(cipherFileName)
	buf, _ := base64.StdEncoding.DecodeString(string(base64Buf))

	keySizes := make(KeySizes, 41)
	for keySize := 2; keySize < 41; keySize++ {
		firstBlock := buf[0:keySize]
		secondBlock := buf[keySize : keySize+keySize]
		hDist := utils.HammingDistance(firstBlock, secondBlock)
		normalized := float64(hDist) / float64(keySize)
		keySizes[keySize] = KeySize{keySize: keySize, score: normalized}
	}
	sort.Sort(keySizes)

	// for each key size,
	for _, keySize := range keySizes[2:6] {
		fmt.Println("------------------------------------")
		fmt.Println("Currently looking at keySize ", keySize.keySize)
		fmt.Println("------------------------------------")

		// break into blocks, then transpose
		blocks := partitionBlocks(buf, keySize.keySize)
		transposedBlocks := transposePartitionedBlocks(blocks)

		// find the single-character byte that produces the best score once XOR'ed
		var likelyKeys [][]byte
		for i := 0; i < len(transposedBlocks); i++ {
			var results []utils.Result = utils.FindXORBytesTopResults(transposedBlocks[i], 3)
			var ks []byte
			var result utils.Result
			result.k
			for _, result = range results {
				ks := append(ks, result.k)
			}
			likelyKeys = append(likelyKeys, ks)
		}

		fmt.Println("Likely key:", likelyKeys)
		//resultingDecryptedBytes := utils.XORRepeatingKey(buf, likelyKey)
		//fmt.Println("output: ", string(resultingDecryptedBytes[0:200]))
	}
}
