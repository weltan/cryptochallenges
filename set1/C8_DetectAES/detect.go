package main

import (
	"fmt"
	"github.com/weltan/cryptochallenges/utils"
)

const cipherFileName = "/Users/ken/code/src/github.com/weltan/cryptochallenges/set1/C8_DetectAES/8.txt"
const cipherFileNameWin = "C:/Users/Ken/Documents/code/src/github.com/weltan/cryptochallenges/set1/C8_DetectAES/8.txt"

func sliceEqual(a, b []byte) bool {
	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for k := 0; k < len(a); k++ {
		if a[k] != b[k] {
			return false
		}
	}

	return true
}

func main() {
	hexBufs := utils.HexFileToBytes(cipherFileName)
	for index, buf := range hexBufs {
		for i := 0; i < len(buf)/16; i++ {
			thisSlice := buf[i*16 : i*16+16]
			for j := i + 1; j < len(buf)/16; j++ {
				thatSlice := buf[j*16 : j*16+16]
				if sliceEqual(thisSlice, thatSlice) {
					fmt.Println("ECB detected for", index)
				}
			}
		}

	}
}
