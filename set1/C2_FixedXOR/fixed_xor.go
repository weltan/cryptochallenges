package crypto

import (
  "encoding/hex"
  "fmt"
)

func XOR(x, y []byte) ([]byte) {
  result := make([]byte, len(x))
  for i, _ := range x {
    var z int = int(x[i]) ^ int(y[i])
    result[i] = byte(z)
  }
  return result
}

func hexXOR(first, second string) {
  firstBytes, err1 := hex.DecodeString(first)
  secondBytes, err2 := hex.DecodeString(second)
  if err1 != nil || err2 != nil {
    fmt.Println("String decoding failed")
  } else {
    fmt.Println(hex.EncodeToString(XOR(firstBytes, secondBytes)))
  }
}

const a = "1c0111001f010100061a024b53535009181c"
const b = "686974207468652062756c6c277320657965"

func main() {
  hexXOR(a, b)
}