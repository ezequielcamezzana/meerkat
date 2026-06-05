package auth

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Legacy tokens (issued before roles, two-field payload) verify as "complete".
func TestVerify_LegacyTwoFieldDefaultsComplete(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	payload := fmt.Sprintf("tenant-1|%d", exp)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	tok := encoded + "." + sign(encoded, "secret")

	tenantID, role, err := Verify(tok, "secret")
	require.NoError(t, err)
	assert.Equal(t, "tenant-1", tenantID)
	assert.Equal(t, "complete", role)
}
