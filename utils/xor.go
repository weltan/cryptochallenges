package utils

import (
	"encoding/hex"
	"errors"
	"fmt"
)

func XOR(x, y []byte) []byte {
	var result = make([]byte, len(x))
	for i, _ := range x {
		var z int = int(x[i]) ^ int(y[i])
		result[i] = byte(z)
	}
	return result
}

func XORKeyByte(x []byte, key byte) []byte {
	var result = make([]byte, len(x))
	for i, _ := range x {
		result[i] = x[i] ^ key
	}
	return result
}

func XORRepeatingKey(target []byte, repeatingKey []byte) []byte {
	var repeatingKeyWithSizeTarget []byte
	for i := 0; i < len(target); i++ {
		keyIdx := i % len(repeatingKey)
		repeatingKeyWithSizeTarget = append(repeatingKeyWithSizeTarget, repeatingKey[keyIdx])
	}
	return XOR(target, repeatingKeyWithSizeTarget)
}

func HexXOR(first, second string) ([]byte, error) {
	firstBytes, err1 := hex.DecodeString(first)
	secondBytes, err2 := hex.DecodeString(second)
	if err1 != nil || err2 != nil {
		fmt.Println("String decoding failed")
		return nil, errors.New("String decoding failed")
	} else {
		return XOR(firstBytes, secondBytes), nil
	}
}
