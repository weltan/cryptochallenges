package main

import (
  "fmt"
)

var testInput string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
var testOutput string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

func charToDec(c string) int {
  switch c[0] {
  case 48:
    return 0
  case 49:
    return 1
  case 50:
    return 2
  case 51:
    return 3
  case 52:
    return 4
  case 53:
    return 5
  case 54:
    return 6
  case 55:
    return 7
  case 56:
    return 8
  case 57:
    return 9
  case 97:
    return 10
  case 98:
    return 11
  case 99:
    return 12
  case 100:
    return 13
  case 101:
    return 14
  case 102:
    return 15
  default:
    return 0
  }
}

func decToBase64(d int) string {
  if d <= 25 {
    return string(byte(d+65))
  } else if d <= 51 {
    return string(byte(d-26+97))
  } else if d <= 61 {
    return string(byte(d-52+48))
  } else if d == 62 {
    return "+"
  } else {
    return "/"
  }
}

func hexToBase64(hex string) string {
  base64str := ""
  //fmt.Print(len(hex)/3)
  for i := 0; i <= len(hex); i += 3 {
    if (i + 3 > len(hex)) {
      // handle padding
    } else {
      byte1 := charToDec(string(hex[i]))
      byte2 := charToDec(string(hex[i+1]))
      byte3 := charToDec(string(hex[i+2]))
      //fmt.Printf("<<%v %v %v>>", byte1, byte2, byte3)
      total := byte1 * 16 * 16 + byte2 * 16 + byte3
      topValue := total / 64
      remainder := total % 64
      base64str += decToBase64(topValue)
      base64str += decToBase64(remainder)
      //fmt.Printf("[%v %v]", decToBase64(topValue), decToBase64(remainder))
      //fmt.Printf("%v " ,string(hex[i:i+3]))
    }
  }
  return base64str
}


func main() {
  result := hexToBase64(testInput)
  fmt.Printf("Expected: %v\n", testOutput)
  fmt.Printf("Result:   %v\n", result)
  if result == testOutput {
    fmt.Println("Success, result matches expected output!")
  } else {
    fmt.Println("Failure, result does not match output.")
  }
}
