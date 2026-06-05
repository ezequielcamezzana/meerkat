package auth_test

import (
	"testing"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/server/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignVerify_RoundTripWithRole(t *testing.T) {
	tok, err := auth.Sign("tenant-1", "guest", "secret", time.Hour)
	require.NoError(t, err)

	tenantID, role, err := auth.Verify(tok, "secret")
	require.NoError(t, err)
	assert.Equal(t, "tenant-1", tenantID)
	assert.Equal(t, "guest", role)
}

func TestVerify_Expired(t *testing.T) {
	tok, err := auth.Sign("tenant-1", "complete", "secret", -time.Minute)
	require.NoError(t, err)

	_, _, err = auth.Verify(tok, "secret")
	assert.ErrorIs(t, err, auth.ErrSessionExpired)
}

func TestVerify_BadSignature(t *testing.T) {
	tok, err := auth.Sign("tenant-1", "complete", "secret", time.Hour)
	require.NoError(t, err)

	_, _, err = auth.Verify(tok, "wrong-secret")
	assert.ErrorIs(t, err, auth.ErrSessionInvalid)
}
