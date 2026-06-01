package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

const (
	Prefix  = "mk_"
	charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	length  = 32
)

// Generate creates a new token and returns (plaintext, hash).
// The plaintext is shown to the user once and never stored.
func Generate() (token, hash string, err error) {
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", "", fmt.Errorf("generating token: %w", err)
		}
		b[i] = charset[n.Int64()]
	}
	token = Prefix + string(b)
	return token, Hash(token), nil
}

func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
