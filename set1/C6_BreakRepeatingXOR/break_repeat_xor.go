package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math"
	"sort"

	"github.com/weltan/cryptochallenges/utils"
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
		firstBlock := buf[0:keySize]
		secondBlock := buf[keySize : keySize+keySize]
		hDist := utils.HammingDistance(firstBlock, secondBlock)
		normalized := float64(hDist) / float64(keySize)
		keySizes[keySize] = KeySize{keySize: keySize, score: normalized}
	}
	sort.Sort(keySizes)
	return keySizes[2:]
}

func main() {

	s := "This is a test."
	sBytes := []byte(s)
	key := []byte{65, 67}
	ciphertext := utils.XORRepeatingKey(sBytes, key)
	fmt.Println("ciphertext in bytes1:", ciphertext)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	fmt.Println("ciphertext as base64:", ciphertextBase64)
	/*
		dst := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
		base64.StdEncoding.Encode(dst, ciphertext)
		ioutil.WriteFile(cipherFileNameWinTest, dst, 0444)
	*/
	base64Buf, _ := ioutil.ReadFile(cipherFileNameWin)
	buf, _ := base64.StdEncoding.DecodeString(string(base64Buf))
	//fmt.Println("ciphertext in bytes2:", buf)
	//decryptedBytes := utils.XORRepeatingKey(buf, key)
	//fmt.Println("Plaintext:", string(decryptedBytes))

	keySizes := findLikelyKeySizes(buf)
	fmt.Println(keySizes)

	var highScore float64
	highScoreText := ""

	// for each key size, partition, transpose and find likely XOR key
	for _, keySize := range keySizes[0:20] {
		fmt.Println("------------------------------------")
		fmt.Println("Currently looking at keySize ", keySize.keySize)
		fmt.Println("------------------------------------")

		// break into blocks, then transpose
		blocks := partitionBlocks(buf, keySize.keySize)
		transposedBlocks := transposePartitionedBlocks(blocks)

		// find the top 3 single-character bytes that produce the best scores once XOR'ed
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

		//fmt.Println("Likely key:", likelyKeys)
		for i := 0; i < int(math.Pow(float64(len(likelyKeys[0])), float64(len(likelyKeys)))); i++ {
			//fmt.Println("i:",i)
			var key []byte
			k := 0
			prevBase := 0
			for j := len(likelyKeys) - 1; j > -1; j-- {
				// calculate jth index
				base := int(math.Pow(float64(len(likelyKeys[0])), float64(j)))

				ith := (i - prevBase) / base
				prevBase += ith * base
				//fmt.Printf("[%v]", ith)
				key = append(key, likelyKeys[k][ith])
				k++
			}
			//fmt.Println("prospective key:", key)
			resultingDecryptedBytes := utils.XORRepeatingKey(buf, key)
			score := utils.EnglishScore(resultingDecryptedBytes)
			if score > highScore {
				highScore = score
				highScoreText = string(resultingDecryptedBytes)
				fmt.Println("new high score!:", string(resultingDecryptedBytes[0:15]))
			}
			//fmt.Println("output: ", string(resultingDecryptedBytes[0:15]))
			/*
				fmt.Println("resultingDecrypteBytes:", resultingDecryptedBytes)
				fmt.Println("decryptedBytes:", decryptedBytes)

				// reverse decrypted bytes to see if you get original base64 string
				encryptedBytes := utils.XORRepeatingKey(decryptedBytes, key)
				cipher := []byte(base64.StdEncoding.EncodeToString(encryptedBytes))
				equal := true
				for i := 0; i < len(cipher); i++ {
					//fmt.Println(string(base64Buf))
					//fmt.Println(string(cipher))
					//fmt.Println("doing test", cipher[i], base64Buf[i])
					if cipher[i] != base64Buf[i] {
						fmt.Println("not equal!")
						equal = false
					}
				}
				if equal {
					fmt.Println("output: ", string(resultingDecryptedBytes[0:15]))
				}
			*/
		}
	}
	fmt.Println("output: ", highScoreText)
}
