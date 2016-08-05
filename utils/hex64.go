package utils

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"log"
	"os"
	"strconv"
)

func ItoHexString(i int) string {
	if i < 10 {
		return strconv.Itoa(i)
	} else {
		switch i {
		case 10:
			return "a"
		case 11:
			return "b"
		case 12:
			return "c"
		case 13:
			return "d"
		case 14:
			return "e"
		case 15:
			return "f"
		}
	}
	return ""
}

func BytesToHexString(result []byte) string {
	return hex.EncodeToString(result)
}

func HexStringToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func Base64ToBytes(fileName string) []byte {
	base64Buf, _ := ioutil.ReadFile(fileName)
	buf, _ := base64.StdEncoding.DecodeString(string(base64Buf))
	return buf
}

// HexFileToBytes takes a fileName with a series of hex sequences on lines, returns an array of byte arrays
func HexFileToBytes(fileName string) [][]byte {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var a [][]byte

	for scanner.Scan() {
		// handle each line of ciphertext
		buf := scanner.Bytes()
		dst := make([]byte, hex.DecodedLen(len(buf)))
		hex.Decode(dst, buf)
		a = append(a, dst)
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return a
}
