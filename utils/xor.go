package utils

import (
  "encoding/hex"
  "fmt"
  "errors"
)

func XOR(x, y []byte) ([]byte) {
  result := make([]byte, len(x))
  for i, _ := range x {
    var z int = int(x[i]) ^ int(y[i])
    result[i] = byte(z)
  }
  return result
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