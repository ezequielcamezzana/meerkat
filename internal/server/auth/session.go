package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const CookieName = "mk_session"

var ErrSessionInvalid = errors.New("invalid session token")
var ErrSessionExpired = errors.New("session expired")

// Sign creates a signed session token encoding tenantID and expiry.
// Format: base64url(tenantID|expUnix).hexHMAC
func Sign(tenantID, secret string, ttl time.Duration) (string, error) {
	exp := time.Now().Add(ttl).Unix()
	payload := fmt.Sprintf("%s|%d", tenantID, exp)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig := sign(encoded, secret)
	return encoded + "." + sig, nil
}

// Verify validates the token signature and expiry, returning the tenantID.
func Verify(token, secret string) (string, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", ErrSessionInvalid
	}
	encoded, sig := parts[0], parts[1]
	if sign(encoded, secret) != sig {
		return "", ErrSessionInvalid
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", ErrSessionInvalid
	}

	idx := strings.LastIndex(string(raw), "|")
	if idx < 0 {
		return "", ErrSessionInvalid
	}
	tenantID := string(raw[:idx])
	expStr := string(raw[idx+1:])

	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return "", ErrSessionInvalid
	}
	if time.Now().Unix() > exp {
		return "", ErrSessionExpired
	}
	return tenantID, nil
}

func sign(payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
