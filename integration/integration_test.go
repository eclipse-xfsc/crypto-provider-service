//lint:file-ignore U1000 Ignore this lint rule for this file

package integration

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/eclipse-xfsc/crypto-provider-service/integration/internal/client"
	"github.com/eclipse-xfsc/crypto-provider-service/internal/config"
	"github.com/eclipse-xfsc/crypto-provider-service/internal/service/signer/jwkvdr"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/web"
	"github.com/kelseyhightower/envconfig"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/engine/core"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/engine/core/types"
)

var (
	cryptoProvider *types.CryptoProvider
	loader         *ld.CachingDocumentLoader
	cfg            config.Config
)

func initTests(t *testing.T) {

	var cfg config.Config
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatalf("cannot load configuration: %v", err)
	}
	var engine types.CryptoProvider
	exPath, _ := os.Getwd()
	enginePath := os.Getenv("ENGINE_PATH")

	if _, err := os.Stat(path.Join(exPath, ".engines")); os.IsNotExist(err) {
		exPath = path.Join(exPath, "..")
	}

	log.Printf(exPath)

	if cfg.Profile == "DEBUG:LOCAL" {
		engine = core.CreateCryptoEngine(path.Join(exPath, ".engines/.local/local-provider.so"))
	} else {
		if cfg.Profile == "DEBUG:VAULT" {
			engine = core.CreateCryptoEngine(path.Join(exPath, ".engines/.vault/hashicorp-vault-provider.so"))
		} else {
			if _, err := os.Stat(enginePath); err == nil || os.IsExist(err) {
				engine = core.CreateCryptoEngine(enginePath)
			} else {
				panic("Engine not exists.")
			}
		}
	}

	require.NotEmpty(t, cfg, "environment variable SIGNER_ADDR is not set")

	if loader == nil {
		loader = ld.NewCachingDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient))
	}

	cryptoProvider = &engine
}

func TestCreateAndVerifyCredentialProof(t *testing.T) {
	initTests(t)

	tests := []struct {
		name   string
		vc     []byte
		errMsg string
	}{
		{
			name:   "valid credential with valid id",
			vc:     []byte(credentialWithSubjectID),
			errMsg: "invalid credential",
		},
		{
			name:   "valid credential without id",
			vc:     []byte(credentialWithoutSubjectID),
			errMsg: "invalid credential",
		},
	}
	signer := client.NewSigner(cryptoProvider, loader)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// create proof
			vcWithProof, err := signer.CreateCredentialLDPVCProof("eckey", test.vc)
			assert.NoError(t, err)
			assert.NotNil(t, vcWithProof)

			// verify signature
			err = signer.VerifyCredentialLDPVcProof(vcWithProof)
			assert.NoError(t, err)

			// parse it to object to modify credentialSubject attribute
			vc, err := verifiable.ParseCredential(
				vcWithProof,
				verifiable.WithJSONLDDocumentLoader(loader),
				verifiable.WithDisabledProofCheck(),
				verifiable.WithStrictValidation(),
				verifiable.WithJSONLDValidation(),
				verifiable.WithJSONLDOnlyValidRDF(),
			)
			assert.NoError(t, err)
			assert.NotNil(t, vc)

			subject, ok := vc.Subject.([]verifiable.Subject)
			assert.True(t, ok)

			// modify the credentialSubject by adding a new value
			subject[0].CustomFields["newKey"] = "newValue" // nolint:goconst

			// marshal the modified credential
			modifiedVC, err := json.Marshal(vc)
			assert.NoError(t, err)
			assert.NotNil(t, modifiedVC)

			err = signer.VerifyCredentialLDPVcProof(modifiedVC)
			if test.errMsg != "" {
				require.Error(t, err, fmt.Sprintf("got no error but expected %q", test.errMsg))
				assert.Contains(t, err.Error(), test.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCreateAndVerifySdJwtCredentialProof(t *testing.T) {
	initTests(t)

	tests := []struct {
		name            string
		vc              []byte
		disclosureFrame []string
		errMsg          string
	}{
		{
			name:            "valid credential with valid id",
			vc:              []byte(sdJwtCredential),
			disclosureFrame: []string{"allow"},
		},
	}
	signer := client.NewSigner(cryptoProvider, loader)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// create proof
			vcWithProof, err := signer.CreateCredentialSdJwtProof("eckey", test.vc)
			assert.NoError(t, err)
			assert.NotNil(t, vcWithProof)

			// verify signature
			err = signer.VerifyCredentialSdJwtProof(vcWithProof, test.disclosureFrame)
			assert.NoError(t, err)
		})
	}
}

func TestCreateAndVerifySdJwtPresentation(t *testing.T) {
	initTests(t)

	tests := []struct {
		name            string
		vc              []byte
		disclosureFrame []string
		errMsg          string
	}{
		{
			name:            "valid credential with valid id",
			vc:              []byte(sdJwtCredential),
			disclosureFrame: []string{"allow"},
		},
	}
	signer := client.NewSigner(cryptoProvider, loader)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// create proof
			vcWithProof, err := signer.CreateCredentialSdJwtProof("eckey", test.vc)
			assert.NoError(t, err)
			assert.NotNil(t, vcWithProof)
			// verify signature
			err = signer.VerifyCredentialSdJwtProof(vcWithProof, test.disclosureFrame)
			assert.NoError(t, err)
			aud := "test"
			nonce := "333"
			vp, err := signer.CreateCredentialSdJwtPresentation("eckey", aud, "", string(vcWithProof), nonce, []string{})
			println(string(vp))

			assert.NoError(t, err)
			assert.NotNil(t, vp)

			err = signer.VerifyPresentationProof(vp, &aud, &nonce, []string{}, "vc+sd-jwt")
			assert.NoError(t, err)
		})
	}
}

func TestCreateCredentialProof(t *testing.T) {
	initTests(t)

	tests := []struct {
		name   string
		vc     []byte
		errMsg string
	}{
		{
			name: "valid credential with subject id",
			vc:   []byte(credentialWithSubjectID),
		},
		{
			name: "valid credential without subject id",
			vc:   []byte(credentialWithoutSubjectID),
		},
		{
			name:   "credential with invalid subject id",
			vc:     []byte(credentialInvalidSubjectID),
			errMsg: "invalid subject id: must be URI",
		},
		{
			name:   "credential with numerical subject id",
			vc:     []byte(credentialWithNumericalSubjectID),
			errMsg: "verifiable credential subject of unsupported format",
		},
		{
			name:   "presentation is given instead of credential",
			vc:     []byte(presentationWithSubjectID),
			errMsg: "verifiable credential is not valid",
		},
	}
	signer := client.NewSigner(cryptoProvider, loader)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			vcWithProof, err := signer.CreateCredentialLDPVCProof("eckey", test.vc)
			if test.errMsg != "" {
				require.Error(t, err, fmt.Sprintf("got no error but expected %q", test.errMsg))
				assert.Contains(t, err.Error(), test.errMsg)
				return
			}

			vc, err := verifiable.ParseCredential(
				vcWithProof,
				verifiable.WithJSONLDDocumentLoader(loader),
				verifiable.WithDisabledProofCheck(),
				verifiable.WithStrictValidation(),
			)
			require.NoError(t, err)
			assert.NotNil(t, vc)

			assert.NotEmpty(t, vc.Proofs)
			assert.NotEmpty(t, vc.Proofs[0]["jws"])
			assert.NotEmpty(t, vc.Proofs[0]["created"])
			assert.NotEmpty(t, vc.Proofs[0]["verificationMethod"])
			assert.Equal(t, "assertionMethod", vc.Proofs[0]["proofPurpose"])
			assert.Equal(t, "JsonWebSignature2020", vc.Proofs[0]["type"])
		})
	}
}

func TestCreateAndVerifyPresentationProof(t *testing.T) {
	initTests(t)

	tests := []struct {
		name   string
		vp     []byte
		errMsg string
	}{
		{
			name:   "presentation with valid credential subject id",
			vp:     []byte(presentationWithSubjectID),
			errMsg: "invalid signature",
		},
		{
			name:   "presentation with valid credential without subject id",
			vp:     []byte(presentationWithoutSubjectID),
			errMsg: "invalid signature",
		},
	}
	signer := client.NewSigner(cryptoProvider, loader)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// create proof
			vpWithProof, err := signer.CreatePresentationProof("eckey", test.vp)
			require.NoError(t, err)
			assert.NotNil(t, vpWithProof)

			// verify signature
			err = signer.VerifyPresentationProof(vpWithProof, nil, nil, nil, "ldp_vc")
			require.NoError(t, err)

			// parse it to object to modify credentialSubject attribute
			vp, err := verifiable.ParsePresentation(
				vpWithProof,
				verifiable.WithPresJSONLDDocumentLoader(loader),
				verifiable.WithPresStrictValidation(),
				verifiable.WithPresDisabledProofCheck(),
			)
			require.NoError(t, err)
			assert.NotNil(t, vp)

			for _, credential := range vp.Credentials() {
				cred, ok := credential.(map[string]interface{})
				assert.True(t, ok)

				if cred["credentialSubject"] == nil {
					continue
				}

				subject, ok := cred["credentialSubject"].(map[string]interface{})
				assert.True(t, ok)

				// modify the credentialSubject by adding a new value
				subject["newKey"] = "newValue"
			}

			// marshal the modified presentation
			modifiedVP, err := json.Marshal(vp)
			assert.NoError(t, err)
			assert.NotNil(t, modifiedVP)

			// verify the signature on the modified presentation
			err = signer.VerifyPresentationProof(modifiedVP, nil, nil, nil, "ldp_vc")
			if test.errMsg != "" {
				require.Error(t, err, fmt.Sprintf("got no error but expected %q", test.errMsg))
				assert.Contains(t, err.Error(), test.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCreatePresentationProof(t *testing.T) {
	initTests(t)

	tests := []struct {
		name   string
		vp     []byte
		errMsg string
	}{
		{
			name: "presentation with credential subject id",
			vp:   []byte(presentationWithSubjectID),
		},
		{
			name: "presentation with credential without subject id",
			vp:   []byte(presentationWithoutSubjectID),
		},
		{
			name:   "presentation with credential with invalid subject id",
			vp:     []byte(presentationWithInvalidSubjectID),
			errMsg: "invalid subject id: must be URI",
		},
		{
			name:   "presentation with credential with numerical subject id",
			vp:     []byte(presentationWithNumericalSubjectID),
			errMsg: "value of @id must be a string",
		},
		{
			name:   "presentation with missing credential context",
			vp:     []byte(presentationWithMissingCredentialContext),
			errMsg: "JSON-LD doc has different structure after compaction",
		},
	}
	signer := client.NewSigner(cryptoProvider, loader)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vpWithProof, err := signer.CreatePresentationProof("eckey", test.vp)
			if test.errMsg != "" {
				require.Error(t, err, fmt.Sprintf("got no error but expected %q", test.errMsg))
				assert.Contains(t, err.Error(), test.errMsg)
				return
			}

			vp, err := verifiable.ParsePresentation(
				vpWithProof,
				verifiable.WithPresJSONLDDocumentLoader(loader),
				verifiable.WithPresStrictValidation(),
				verifiable.WithPresDisabledProofCheck(),
			)
			require.NoError(t, err)
			assert.NotNil(t, vp)

			assert.NotEmpty(t, vp.Proofs)
			assert.NotEmpty(t, vp.Proofs[0]["jws"])
			assert.NotEmpty(t, vp.Proofs[0]["created"])
			assert.NotEmpty(t, vp.Proofs[0]["verificationMethod"])
			assert.Equal(t, "assertionMethod", vp.Proofs[0]["proofPurpose"])
			assert.Equal(t, "JsonWebSignature2020", vp.Proofs[0]["type"])
		})
	}
}

func TestCreateCredential(t *testing.T) {
	initTests(t)

	tests := []struct {
		name     string
		req      map[string]interface{}
		contexts []string
		errtext  string
	}{
		{
			name: "valid request with single credentialSubject claim",
			req: map[string]interface{}{
				"issuer":            "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
				"namespace":         "transit",
				"holder":            "eyJhbGciOiJFZERTQSIsImp3ayI6eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiIyZjE0NTEwMi0yMGU0LTRjYzQtYjE1OS01OWUyZTIwYzQ2NGYiLCJrdHkiOiJPS1AiLCJ4Ijoianl4VVpLQjNIUjVfLTNJa1A1VEFLeTh2SXVoX192dko4OG5CZjFDcFV1byJ9LCJraWQiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlpFUlRRU0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0pyYVdRaU9pSXlaakUwTlRFd01pMHlNR1UwTFRSall6UXRZakUxT1MwMU9XVXlaVEl3WXpRMk5HWWlMQ0pyZEhraU9pSlBTMUFpTENKNElqb2lhbmw0VlZwTFFqTklValZmTFROSmExQTFWRUZMZVRoMlNYVm9YMTkyZGtvNE9HNUNaakZEY0ZWMWJ5SjkiLCJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCJ9.eyJhdWQiOlsiaHR0cHM6Ly9jbG91ZC13YWxsZXQueGZzYy5kZXYiXSwiaWF0IjoxNzI3MjQ4OTc2LCJub25jZSI6ImRhYzRhODFlLWUyNjItNDkzMS1hODA2LWY0NGFmMWIzMjE4NyJ9.0chMgVQ_NvPpB3VF-pjp4ib0aMpRvepx1dcW45CC1J1PAxyg_wEhD24yDQ-o6Dxp-Qp5c9RhRRe1oG1uw8w3Cg",
				"key":               "eckey",
				"format":            "ldp_vc",
				"credentialSubject": map[string]interface{}{"cred1": "value1"},
			},
		},
		{
			name: "valid request with multiple credentialSubject claims",
			req: map[string]interface{}{
				"issuer":    "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
				"namespace": "transit",
				"format":    "ldp_vc",
				"holder":    "urn:dfjdfjdf:22333",
				"key":       "eckey",
				"credentialSubject": map[string]interface{}{
					"cred1": "value1",
					"cred2": "value2",
				},
			},
		},
		{
			name: "valid request with multiple credentialSubject claims and status",
			req: map[string]interface{}{
				"issuer":    "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
				"namespace": "transit",
				"format":    "ldp_vc",
				"status":    true,
				"holder":    "urn:dfjdfjdf:22333",
				"key":       "eckey",
				"credentialSubject": map[string]interface{}{
					"cred1": "value1",
					"cred2": "value2",
				},
			},
		},
		{
			name: "valid request sd jwt format",
			req: map[string]interface{}{
				"issuer":    "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
				"namespace": "transit",
				"format":    "vc+sd-jwt",
				"holder":    "eyJhbGciOiJFZERTQSIsImp3ayI6eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiIyZjE0NTEwMi0yMGU0LTRjYzQtYjE1OS01OWUyZTIwYzQ2NGYiLCJrdHkiOiJPS1AiLCJ4Ijoianl4VVpLQjNIUjVfLTNJa1A1VEFLeTh2SXVoX192dko4OG5CZjFDcFV1byJ9LCJraWQiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlpFUlRRU0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0pyYVdRaU9pSXlaakUwTlRFd01pMHlNR1UwTFRSall6UXRZakUxT1MwMU9XVXlaVEl3WXpRMk5HWWlMQ0pyZEhraU9pSlBTMUFpTENKNElqb2lhbmw0VlZwTFFqTklValZmTFROSmExQTFWRUZMZVRoMlNYVm9YMTkyZGtvNE9HNUNaakZEY0ZWMWJ5SjkiLCJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCJ9.eyJhdWQiOlsiaHR0cHM6Ly9jbG91ZC13YWxsZXQueGZzYy5kZXYiXSwiaWF0IjoxNzI3MjQ4OTc2LCJub25jZSI6ImRhYzRhODFlLWUyNjItNDkzMS1hODA2LWY0NGFmMWIzMjE4NyJ9.0chMgVQ_NvPpB3VF-pjp4ib0aMpRvepx1dcW45CC1J1PAxyg_wEhD24yDQ-o6Dxp-Qp5c9RhRRe1oG1uw8w3Cg",
				"key":       "eckey",
				"credentialSubject": map[string]interface{}{
					"cred1": "value1",
					"cred2": "value2",
				},
				"type": []string{"VerifiableCredential", "testbla"},
			},
		},
		{
			name: "valid request sd jwt format and status",
			req: map[string]interface{}{
				"issuer":    "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
				"namespace": "transit",
				"status":    true,
				"format":    "vc+sd-jwt",
				"holder":    "eyJhbGciOiJFZERTQSIsImp3ayI6eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiIyZjE0NTEwMi0yMGU0LTRjYzQtYjE1OS01OWUyZTIwYzQ2NGYiLCJrdHkiOiJPS1AiLCJ4Ijoianl4VVpLQjNIUjVfLTNJa1A1VEFLeTh2SXVoX192dko4OG5CZjFDcFV1byJ9LCJraWQiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlpFUlRRU0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0pyYVdRaU9pSXlaakUwTlRFd01pMHlNR1UwTFRSall6UXRZakUxT1MwMU9XVXlaVEl3WXpRMk5HWWlMQ0pyZEhraU9pSlBTMUFpTENKNElqb2lhbmw0VlZwTFFqTklValZmTFROSmExQTFWRUZMZVRoMlNYVm9YMTkyZGtvNE9HNUNaakZEY0ZWMWJ5SjkiLCJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCJ9.eyJhdWQiOlsiaHR0cHM6Ly9jbG91ZC13YWxsZXQueGZzYy5kZXYiXSwiaWF0IjoxNzI3MjQ4OTc2LCJub25jZSI6ImRhYzRhODFlLWUyNjItNDkzMS1hODA2LWY0NGFmMWIzMjE4NyJ9.0chMgVQ_NvPpB3VF-pjp4ib0aMpRvepx1dcW45CC1J1PAxyg_wEhD24yDQ-o6Dxp-Qp5c9RhRRe1oG1uw8w3Cg",
				"key":       "eckey",
				"credentialSubject": map[string]interface{}{
					"cred1": "value1",
					"cred2": "value2",
				},
				"type": []string{"VerifiableCredential", "testbla"},
			},
		},
	}

	signer := client.NewSigner(cryptoProvider, loader)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reqData, err := json.Marshal(test.req)
			require.NoError(t, err)

			vcWithProof, err := signer.CreateCredentialPlain(reqData)
			println(string(vcWithProof))
			if test.errtext != "" {
				require.Error(t, err, fmt.Sprintf("got no error but expected %q", test.errtext))
				assert.Contains(t, err.Error(), test.errtext)
				return
			}

			if test.req["format"] != "ldp_vc" {
				return
			}

			vc, err := verifyCredentialProofs(vcWithProof)
			require.NoError(t, err)
			assert.NotNil(t, vc)

			assert.NotEmpty(t, vc.Proofs)
			assert.NotEmpty(t, vc.Proofs[0]["jws"])
			assert.NotEmpty(t, vc.Proofs[0]["created"])
			assert.NotEmpty(t, vc.Proofs[0]["verificationMethod"])
			assert.Equal(t, "assertionMethod", vc.Proofs[0]["proofPurpose"])
			assert.Equal(t, "JsonWebSignature2020", vc.Proofs[0]["type"])

			// hyperledger aries always parse the subject map into an array (unless it's just a string)
			subject, ok := vc.Subject.([]verifiable.Subject)
			assert.True(t, ok)

			expectedClaims, ok := test.req["credentialSubject"].(map[string]interface{})
			assert.True(t, ok)
			assert.Equal(t, len(expectedClaims), len(subject[0].CustomFields))

			for key := range expectedClaims {
				assert.Equal(t, expectedClaims[key], subject[0].CustomFields[key])
			}
		})
	}
}

func TestCreatePresentation(t *testing.T) {

	initTests(t)

	tests := []struct {
		name     string
		req      map[string]interface{}
		contexts []string
		errtext  string
	}{
		{
			name: "invalid request",
			req: map[string]interface{}{
				"namespace":     "transit",
				"signatureType": "jsonwebsignature2020",
				"key":           "key1",
				"data": []map[string]interface{}{
					{"cred1": "value1"},
				},
			},
			errtext: "400 Bad Request",
		},
		{
			name: "valid request with single credentialSubject entry",
			req: map[string]interface{}{
				"issuer":        "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
				"namespace":     "transit",
				"signatureType": "jsonwebsignature2020",
				"key":           "eckey",
				"data": []map[string]interface{}{
					{"cred1": "value1"},
				},
			},
		},
		{
			name: "valid request with multiple credentialSubject entry",
			req: map[string]interface{}{
				"issuer":        "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
				"namespace":     "transit",
				"signatureType": "jsonwebsignature2020",
				"key":           "eckey",
				"data": []map[string]interface{}{
					{"cred1": "value1"},
					{"cred2": "value2"},
				},
			},
		},
		{
			name: "valid request with additional context",
			req: map[string]interface{}{
				"issuer":        "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
				"namespace":     "transit",
				"key":           "eckey",
				"signatureType": "jsonwebsignature2020",
				"context": []string{
					"https://schema.org",
				},
				"data": []map[string]interface{}{
					{"cred1": "value1"},
					{"cred2": "value2"},
				},
			},
		},
	}

	signer := client.NewSigner(cryptoProvider, loader)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reqData, err := json.Marshal(test.req)
			require.NoError(t, err)

			vpWithProof, err := signer.CreatePresentationPlain(reqData)
			if test.errtext != "" {
				require.Error(t, err, fmt.Sprintf("got no error but expected %q", test.errtext))
				assert.Contains(t, err.Error(), test.errtext)
				return
			}

			vp, err := verifiable.ParsePresentation(
				vpWithProof,
				verifiable.WithPresJSONLDDocumentLoader(loader),
				verifiable.WithPresStrictValidation(),
				verifiable.WithPresDisabledProofCheck(),
			)
			require.NoError(t, err)
			assert.NotNil(t, vp)

			assert.NotEmpty(t, vp.Proofs)
			assert.NotEmpty(t, vp.Proofs[0]["jws"])
			assert.NotEmpty(t, vp.Proofs[0]["created"])
			assert.NotEmpty(t, vp.Proofs[0]["verificationMethod"])
			assert.Equal(t, "assertionMethod", vp.Proofs[0]["proofPurpose"])
			assert.Equal(t, "JsonWebSignature2020", vp.Proofs[0]["type"])

			creds := vp.Credentials()
			requiredCreds, ok := test.req["data"].([]map[string]interface{})
			assert.True(t, ok)
			assert.Equal(t, len(requiredCreds), len(creds))

			for i, cred := range creds {
				c, ok := cred.(map[string]interface{})
				assert.True(t, ok)

				subject, ok := c["credentialSubject"].(map[string]interface{})
				assert.True(t, ok)
				assert.Equal(t, requiredCreds[i], subject)
			}
		})
	}
}

func TestCreateCredentialMultipleProofs(t *testing.T) {

	initTests(t)
	signer := client.NewSigner(cryptoProvider, loader)

	cred := []byte(credentialWithSubjectID)

	// create first proof
	vcWithProof, err := signer.CreateCredentialLDPVCProof("eckey", cred)
	assert.NoError(t, err)
	assert.NotNil(t, vcWithProof)

	// verify signature
	_, err = verifyCredentialProofs(vcWithProof)
	assert.NoError(t, err)

	// create second proof
	vc2Proofs, err := signer.CreateCredentialLDPVCProof("eckey", vcWithProof)
	assert.NoError(t, err)
	assert.NotNil(t, vc2Proofs)

	// verify signatures
	_, err = verifyCredentialProofs(vc2Proofs)
	require.NoError(t, err)

	// run tests modifying the contents of the VC and do proof verifications afterwards

	t.Run("modify credential subject and check proofs afterwards", func(t *testing.T) {
		correctVC := make([]byte, len(vc2Proofs))
		copy(correctVC, vc2Proofs)

		parsedVC, err := verifyCredentialProofs(correctVC)
		assert.NoError(t, err)

		// modify the credentialSubject by adding a new value
		// which MUST break signature verification
		subject, ok := parsedVC.Subject.([]verifiable.Subject)
		assert.True(t, ok)

		subject[0].CustomFields["newKey"] = "newValue"

		// marshal the modified credential
		modifiedVC, err := json.Marshal(parsedVC)
		assert.NoError(t, err)
		assert.NotNil(t, modifiedVC)

		_, err = verifyCredentialProofs(modifiedVC)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature")
	})

	t.Run("modify first signature and check proofs afterwards", func(t *testing.T) {
		correctVC := make([]byte, len(vc2Proofs))
		copy(correctVC, vc2Proofs)

		parsedVC, err := verifyCredentialProofs(correctVC)
		assert.NoError(t, err)

		// modify JWS value of the first proof by removing the last character
		proof1 := parsedVC.Proofs[0]
		if jws, ok := proof1["jws"].(string); ok && jws != "" {
			modifiedSignature, err := modifySignature(jws)
			require.NoError(t, err)
			parsedVC.Proofs[0]["jws"] = modifiedSignature
		} else {
			t.Errorf("expected to have proof 1 but it's missing or invalid")
		}

		// marshal the modified credential
		modifiedVC, err := json.Marshal(parsedVC)
		assert.NoError(t, err)
		assert.NotNil(t, modifiedVC)

		_, err = verifyCredentialProofs(modifiedVC)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature")
	})

	t.Run("modifiy second signature and check proofs afterwards", func(t *testing.T) {
		correctVC := make([]byte, len(vc2Proofs))
		copy(correctVC, vc2Proofs)

		parsedVC, err := verifyCredentialProofs(correctVC)
		assert.NoError(t, err)

		// modify JWS value of the second proof by removing the last character
		proof2 := parsedVC.Proofs[1]
		if jws, ok := proof2["jws"].(string); ok && jws != "" {
			modifiedSignature, err := modifySignature(jws)
			require.NoError(t, err)
			parsedVC.Proofs[1]["jws"] = modifiedSignature
		} else {
			t.Errorf("expected to have proof 2 but it's missing or invalid")
		}

		// marshal the modified credential
		modifiedVC, err := json.Marshal(parsedVC)
		assert.NoError(t, err)
		assert.NotNil(t, modifiedVC)

		_, err = verifyCredentialProofs(modifiedVC)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature")
	})
}

func verifyCredentialProofs(vcBytes []byte) (*verifiable.Credential, error) {
	webVDR := web.New()
	keyVDR := key.New()
	jwkVDR := jwkvdr.New()
	registry := vdr.New(
		vdr.WithVDR(webVDR),
		vdr.WithVDR(keyVDR),
		vdr.WithVDR(jwkVDR),
	)
	keyResolver := verifiable.NewVDRKeyResolver(registry)

	// parse it to object to modify credentialSubject attribute
	vc, err := verifiable.ParseCredential(
		vcBytes,
		verifiable.WithJSONLDDocumentLoader(loader),
		verifiable.WithStrictValidation(),
		verifiable.WithJSONLDValidation(),
		verifiable.WithJSONLDOnlyValidRDF(),
		verifiable.WithPublicKeyFetcher(keyResolver.PublicKeyFetcher()),
	)

	return vc, err
}

func modifySignature(jws string) (string, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid jws signature")
	}

	modifiedJWS := parts[0] + "." + parts[1] + "." + "8hiz2aWSW_AWnZ_GnoQyHrYgGia0HxdYTQGYOVYkPLU"

	return modifiedJWS, nil
}
