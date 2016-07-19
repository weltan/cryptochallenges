package main

import (
	"fmt"
	"github.com/weltan/cryptochallenges/utils"
)

const cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

func main() {
	result, _, key := utils.FindXOR(cipher)
	fmt.Println("Decrypted string: ", string(result))
	fmt.Println("Key (in ASCII): ", string(key))
}
