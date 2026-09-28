package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// The stored hash of a secret against the secret presented. Compared in
// constant time: a byte-by-byte comparison leaks where it stopped.
func sameHash(stored, presented string) bool {
	sum := sha256.Sum256([]byte(presented))
	return hmac.Equal([]byte(stored), []byte(hex.EncodeToString(sum[:])))
}
