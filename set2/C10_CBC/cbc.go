package main

import (
	"encoding/base64"
	"fmt"
	"github.com/weltan/cryptochallenges/utils"
	"io/ioutil"
)

const filename string = "/Users/ken/code/src/github.com/weltan/cryptochallenges/set2/C10_CBC/10.txt"

func main() {
	buf, _ := ioutil.ReadFile(filename)
	ciphertext, _ := base64.StdEncoding.DecodeString((string(buf)))
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)

	result, _ := utils.CBCAes128Decrypt(ciphertext, key, iv)
	fmt.Println(string(result))
}
