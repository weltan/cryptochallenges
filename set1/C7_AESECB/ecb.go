package main

import (
	"fmt"
	"github.com/weltan/cryptochallenges/utils"
	"log"
)

const cipherFileName = "/Users/ken/code/src/github.com/weltan/cryptochallenges/set1/C7_AESECB/7.txt"
const cipherFileNameWin = "C:/Users/Ken/Documents/code/src/github.com/weltan/cryptochallenges/set1/C7_AESECB/7.txt"

func testAes128() {
	var input = []byte{
		'\x00', '\x11', '\x22', '\x33', '\x44', '\x55', '\x66', '\x77',
		'\x88', '\x99', '\xaa', '\xbb', '\xcc', '\xdd', '\xee', '\xff'}

	var key = []byte{
		'\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',
		'\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f'}

	// test encryption
	ciphertext, err := utils.Aes128Encrypt(input, key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(utils.BytesToHexString(ciphertext))

	// test decryption
	plaintext, err := utils.Aes128Decrypt(ciphertext, key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(utils.BytesToHexString(plaintext))
}

func main() {
	key := []byte("YELLOW SUBMARINE")
	buf := utils.Base64ToBytes(cipherFileName)
	for i := 0; i < len(buf)/16; i++ {
		plaintext, err := utils.Aes128Decrypt(buf[i*16:i*16+16], key)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf(string(plaintext))
	}
}
