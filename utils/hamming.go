package utils

func HammingDistance(a, b []byte) int {
	hammingCount := 0
	for i := 0; i < len(a); i++ {
		d := 0
		var a byte = a[i] ^ b[i]
		var j uint
		for j = 0; j < 8; j++ {
			if ((a >> j) % 2) != 0 {
				d++
			}
		}
		hammingCount += d
	}
	return hammingCount
}

func StringHammingDistance(a, b string) int {
	aBytes := []byte(a)
	bBytes := []byte(b)
	return HammingDistance(aBytes, bBytes)
}
