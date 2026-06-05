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

// Sign creates a signed session token encoding tenantID, expiry and role.
// Format: base64url(tenantID|expUnix|role).hexHMAC
func Sign(tenantID, role, secret string, ttl time.Duration) (string, error) {
	exp := time.Now().Add(ttl).Unix()
	payload := fmt.Sprintf("%s|%d|%s", tenantID, exp, role)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig := sign(encoded, secret)
	return encoded + "." + sig, nil
}

// Verify validates the token signature and expiry, returning the tenantID and role.
// Tokens issued before roles existed (two-field payload) verify as "complete".
func Verify(token, secret string) (tenantID, role string, err error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", "", ErrSessionInvalid
	}
	encoded, sig := parts[0], parts[1]
	if sign(encoded, secret) != sig {
		return "", "", ErrSessionInvalid
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", ErrSessionInvalid
	}

	// payload: tenantID|expUnix[|role] — tenantID (UUID) and role have no "|".
	fields := strings.Split(string(raw), "|")
	if len(fields) < 2 {
		return "", "", ErrSessionInvalid
	}
	tenantID = fields[0]
	role = "complete"
	if len(fields) >= 3 {
		role = fields[2]
	}

	exp, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return "", "", ErrSessionInvalid
	}
	if time.Now().Unix() > exp {
		return "", "", ErrSessionExpired
	}
	return tenantID, role, nil
}

func sign(payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
