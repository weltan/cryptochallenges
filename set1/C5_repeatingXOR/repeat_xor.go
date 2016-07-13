package main

import (
	"fmt"
	"github.com/weltan/cryptochallenges/utils"
)

const stanza = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

func main() {
	key := []byte("ICE")
	stanzaBytes := []byte(stanza)

	result := utils.KeyXOR(stanzaBytes, key)
	fmt.Println(utils.BytesToHexString(result))
}
