package main

import (
	"fmt"
	"github.com/weltan/cryptochallenges/utils"
)

const stanza = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

func main() {
	repeatingKey := []byte("ICE")
	stanzaBytes := []byte(stanza)

	result := utils.XORRepeatingKey(stanzaBytes, repeatingKey)
	fmt.Println(utils.BytesToHexString(result))
}
