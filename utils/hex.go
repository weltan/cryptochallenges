package utils

import (
	"strconv"
)

func ItoHexString(i int) (string) {
	if i < 10  {
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