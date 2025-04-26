package verify_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/eclipse-xfsc/crypto-provider-service/internal/verify"
	"github.com/eclipse-xfsc/crypto-provider-service/internal/verify/train"
)

func TestNew(t *testing.T) {
	// unknown credential verifier
	names := []string{"unknown verifier"}
	_, err := verify.New(names, http.DefaultClient, "addr", []string{"schema1"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown credential verifier")

	// no verifiers specified
	names = []string{}
	vs, err := verify.New(names, http.DefaultClient, "addr", []string{"schema1"})
	assert.NoError(t, err)
	assert.Empty(t, vs)

	// train verifier created successfully
	names = []string{"TRAIN"}
	vs, err = verify.New(names, http.DefaultClient, "addr", []string{"schema1"})
	assert.NoError(t, err)
	assert.NotEmpty(t, vs)
	_, ok := vs[0].(*train.Verifier)
	assert.True(t, ok)
}
