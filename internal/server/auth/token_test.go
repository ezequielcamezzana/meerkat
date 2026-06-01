package auth_test

import (
	"strings"
	"testing"

	"github.com/ezequielcamezzana/meerkat/internal/server/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	token, hash, err := auth.Generate()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(token, auth.Prefix))
	assert.Len(t, token, len(auth.Prefix)+32)
	assert.Equal(t, auth.Hash(token), hash)
}

func TestGenerate_Unique(t *testing.T) {
	t1, _, _ := auth.Generate()
	t2, _, _ := auth.Generate()
	assert.NotEqual(t, t1, t2)
}

func TestHash_Idempotent(t *testing.T) {
	assert.Equal(t, auth.Hash("mk_abc"), auth.Hash("mk_abc"))
	assert.NotEqual(t, auth.Hash("mk_abc"), auth.Hash("mk_xyz"))
}
