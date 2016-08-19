package main

import (
	"bytes"
	"fmt"
	"github.com/weltan/cryptochallenges/utils"
)

func main() {
	plaintext := []byte("YELLOW SUBMARINE1asdlfkajsdlkfjasdlkfjasdlkfjsadf")
	key := []byte("YELLOW SUBMARINE")

	result, _ := utils.ECBAes128Encrypt(plaintext, key)
	returnTripPlaintext, _ := utils.ECBAes128Decrypt(result, key)

	// test round trip again
	result2, _ := utils.ECBAes128Encrypt(returnTripPlaintext, key)
	returnTripPlaintext2, _ := utils.ECBAes128Decrypt(result2, key)

	if bytes.Equal(returnTripPlaintext, returnTripPlaintext2) {
		fmt.Println("Passed padding test")
	} else {
		fmt.Println("Failed padding test")
	}
}
