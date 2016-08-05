package utils

import (
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
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

func Base64ToBytes(fileName string) []byte {
	base64Buf, _ := ioutil.ReadFile(fileName)
	buf, _ := base64.StdEncoding.DecodeString(string(base64Buf))
	return buf
}
