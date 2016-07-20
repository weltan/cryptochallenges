package utils

func HammingDistance(a, b []byte) int {
	hammingCount := 0
	xor := XOR(a, b)
	for i := 0; i < len(xor); i++ {
		for j := uint(0); j < 8; j++ {
			if ((xor[i] >> j) % 2) != 0 {
				hammingCount++
			}
		}
	}
	return hammingCount
}

func StringHammingDistance(a, b string) int {
	aBytes := []byte(a)
	bBytes := []byte(b)
	return HammingDistance(aBytes, bBytes)
}
