package train_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-xfsc/crypto-provider-service/internal/verify/train"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/golib/errors"
)

func TestNew(t *testing.T) {
	// error empty address
	_, err := train.New(http.DefaultClient, "", []string{"schema1"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "train server address cannot be empty")

	// verifier is created successfully
	v, err := train.New(http.DefaultClient, "addr", []string{"schema1"})
	assert.NoError(t, err)
	assert.NotNil(t, v)

}

func TestVerifier_VerifyCredential(t *testing.T) {
	tests := []struct {
		name string

		vc      *verifiable.Credential
		handler http.HandlerFunc

		errkind errors.Kind
		errtext string
	}{
		{
			name:    "empty terms of use",
			vc:      &verifiable.Credential{TermsOfUse: nil},
			errkind: errors.BadRequest,
			errtext: "terms of use cannot be empty",
		},
		{
			name: "trust scheme field is not an array",
			vc: &verifiable.Credential{TermsOfUse: []verifiable.TypedID{
				{
					ID:   "did:web:notary.company1.com",
					Type: "train",
					CustomFields: map[string]interface{}{
						"trustScheme": "scheme1",
					},
				},
			}},
			errkind: errors.BadRequest,
			errtext: "invalid terms of use: trustScheme field is expected to be an array",
		},
		{
			name: "trust scheme array is empty",
			vc: &verifiable.Credential{TermsOfUse: []verifiable.TypedID{
				{
					ID:   "did:web:notary.company1.com",
					Type: "train",
					CustomFields: map[string]interface{}{
						"trustScheme": []interface{}{},
					},
				},
			}},
			errkind: errors.BadRequest,
			errtext: "invalid terms of use: trustScheme field cannot be empty",
		},
		{
			name: "unsupported trust scheme",
			vc: &verifiable.Credential{TermsOfUse: []verifiable.TypedID{
				{
					ID:   "did:web:notary.company1.com",
					Type: "train",
					CustomFields: map[string]interface{}{
						"trustScheme": []interface{}{"unknown scheme"},
					},
				},
			}},
			errkind: errors.BadRequest,
			errtext: "invalid terms of use: unsupported trust scheme",
		},
		{
			name: "error when calling train service",
			vc: &verifiable.Credential{TermsOfUse: []verifiable.TypedID{
				{
					ID:   "did:web:notary.company1.com",
					Type: "train",
					CustomFields: map[string]interface{}{
						"trustScheme": []interface{}{"trusted scheme 1"},
					},
				},
			}},
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Add("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)

				// this is an imperative error response syntax
				_, _ = w.Write([]byte(`{"code":"500","message":"internal error"}`))
			},
			errkind: errors.Internal,
			errtext: "500 Internal Server Error",
		},
		{
			name: "did is not verified error",
			vc: &verifiable.Credential{TermsOfUse: []verifiable.TypedID{
				{
					ID:   "did:web:notary.company1.com",
					Type: "train",
					CustomFields: map[string]interface{}{
						"trustScheme": []interface{}{"trusted scheme 1"},
					},
				},
			}},
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Add("Content-Type", "application/json")
				_, _ = w.Write([]byte(trainServerResp("false", "true")))
			},
			errkind: errors.Unknown,
			errtext: "train validation failed: did is not verified",
		},
		{
			name: "VC is not verified",
			vc: &verifiable.Credential{TermsOfUse: []verifiable.TypedID{
				{
					ID:   "did:web:notary.company1.com",
					Type: "train",
					CustomFields: map[string]interface{}{
						"trustScheme": []interface{}{"trusted scheme 1"},
					},
				},
			}},
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Add("Content-Type", "application/json")
				_, _ = w.Write([]byte(trainServerResp("true", "false")))
			},
			errkind: errors.Unknown,
			errtext: "train validation failed: endpoint VC is not verified",
		},
		{
			name: "credential validation is successful",
			vc: &verifiable.Credential{TermsOfUse: []verifiable.TypedID{
				{
					ID:   "did:web:notary.company1.com",
					Type: "train",
					CustomFields: map[string]interface{}{
						"trustScheme": []interface{}{"trusted scheme 1"},
					},
				},
			}},
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Add("Content-Type", "application/json")
				_, _ = w.Write([]byte(trainServerResp("true", "true")))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv := httptest.NewServer(test.handler)
			defer srv.Close()

			v, err := train.New(http.DefaultClient, srv.URL, []string{"trusted scheme 1", "trusted scheme 2"})
			assert.NoError(t, err)

			err = v.VerifyCredential(context.Background(), test.vc)
			if err != nil {
				require.NotEmpty(t, test.errtext, "expected no error but got %s", err)
				assert.ErrorContains(t, err, test.errtext)
				e, ok := err.(*errors.Error)
				require.True(t, ok)
				assert.Equal(t, test.errkind, e.Kind)
				return
			}

			// success
			require.Empty(t, test.errtext, "got no error, but expected: %s", test.errtext)
			assert.NoError(t, err)
		})
	}
}

func TestVerifier_VerifyPresentation(t *testing.T) {
	tests := []struct {
		name string

		vp      *verifiable.Presentation
		handler http.HandlerFunc

		errkind errors.Kind
		errtext string
	}{
		{
			name:    "terms of use are not set in request",
			vp:      &verifiable.Presentation{CustomFields: map[string]interface{}{}},
			errkind: errors.BadRequest,
			errtext: "terms of use must be an array",
		},
		{
			name:    "empty terms of use",
			vp:      &verifiable.Presentation{CustomFields: map[string]interface{}{"termsOfUse": []interface{}{}}},
			errkind: errors.BadRequest,
			errtext: "terms of use cannot be empty",
		},
		{
			name: "invalid terms of use",
			vp: &verifiable.Presentation{CustomFields: map[string]interface{}{
				"termsOfUse": []interface{}{
					"string",
				},
			}},
			errkind: errors.BadRequest,
			errtext: "invalid terms of use: must contain an array of map",
		},
		{
			name: "missing issuer ID in terms of use",
			vp: &verifiable.Presentation{CustomFields: map[string]interface{}{
				"termsOfUse": []interface{}{
					map[string]interface{}{},
				},
			}},
			errkind: errors.BadRequest,
			errtext: "invalid terms of use: missing id key",
		},
		{
			name: "missing trustScheme in terms of use",
			vp: &verifiable.Presentation{CustomFields: map[string]interface{}{
				"termsOfUse": []interface{}{
					map[string]interface{}{
						"id": "some ID",
					},
				},
			}},
			errkind: errors.BadRequest,
			errtext: "invalid terms of use: trustScheme field is expected",
		},
		{
			name: "empty trustScheme in terms of use",
			vp: &verifiable.Presentation{CustomFields: map[string]interface{}{
				"termsOfUse": []interface{}{
					map[string]interface{}{
						"id":          "some ID",
						"trustScheme": []interface{}{},
					},
				},
			}},
			errkind: errors.BadRequest,
			errtext: "invalid terms of use: trustScheme field cannot be empty",
		},
		{
			name: "unsupported trust scheme",
			vp: &verifiable.Presentation{CustomFields: map[string]interface{}{
				"termsOfUse": []interface{}{
					map[string]interface{}{
						"id":          "did:web:notary.company1.com",
						"trustScheme": []interface{}{"unknown scheme"},
					},
				},
			}},
			errkind: errors.BadRequest,
			errtext: "invalid terms of use: unsupported trust scheme",
		},
		{
			name: "error when calling train service",
			vp: &verifiable.Presentation{CustomFields: map[string]interface{}{
				"termsOfUse": []interface{}{
					map[string]interface{}{
						"id":          "did:web:notary.company1.com",
						"trustScheme": []interface{}{"trusted scheme 1"},
					},
				},
			}},
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Add("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)

				// this is an imperative error response syntax
				_, _ = w.Write([]byte(`{"code":"500","message":"internal error"}`))
			},
			errkind: errors.Internal,
			errtext: "500 Internal Server Error",
		},
		{
			name: "did is not verified error",
			vp: &verifiable.Presentation{CustomFields: map[string]interface{}{
				"termsOfUse": []interface{}{
					map[string]interface{}{
						"id":          "did:web:notary.company1.com",
						"trustScheme": []interface{}{"trusted scheme 1"},
					},
				},
			}},
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Add("Content-Type", "application/json")
				_, _ = w.Write([]byte(trainServerResp("false", "true")))
			},
			errkind: errors.Unknown,
			errtext: "train validation failed: did is not verified",
		},
		{
			name: "VC in train response is not verified",
			vp: &verifiable.Presentation{CustomFields: map[string]interface{}{
				"termsOfUse": []interface{}{
					map[string]interface{}{
						"id":          "did:web:notary.company1.com",
						"trustScheme": []interface{}{"trusted scheme 1"},
					},
				},
			}},
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Add("Content-Type", "application/json")
				_, _ = w.Write([]byte(trainServerResp("true", "false")))
			},
			errkind: errors.Unknown,
			errtext: "train validation failed: endpoint VC is not verified",
		},
		{
			name: "VP is verified successfully",
			vp: &verifiable.Presentation{CustomFields: map[string]interface{}{
				"termsOfUse": []interface{}{
					map[string]interface{}{
						"id":          "did:web:notary.company1.com",
						"trustScheme": []interface{}{"trusted scheme 1"},
					},
				},
			}},
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Add("Content-Type", "application/json")
				_, _ = w.Write([]byte(trainServerResp("true", "true")))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv := httptest.NewServer(test.handler)
			defer srv.Close()

			v, err := train.New(http.DefaultClient, srv.URL, []string{"trusted scheme 1", "trusted scheme 2"})
			assert.NoError(t, err)

			err = v.VerifyPresentation(context.Background(), test.vp)
			if err != nil {
				require.NotEmpty(t, test.errtext, "expected no error but got %s", err)
				assert.ErrorContains(t, err, test.errtext)
				e, ok := err.(*errors.Error)
				require.True(t, ok)
				assert.Equal(t, test.errkind, e.Kind)
				return
			}

			// success
			require.Empty(t, test.errtext, "got no error, but expected: %s", test.errtext)
			assert.NoError(t, err)
		})
	}

}

func trainServerResp(didVerified string, vcVerified string) string {
	var resp = `{
   "trustSchemePointers": [
       {
           "pointer": "gxfs.test.train.trust-scheme.de",
           "dids": [
               "did:web:essif.iao.fraunhofer.de"
           ],
           "error": null
       }
   ],
   "resolvedResults": [
       {
           "did": "did:web:essif.iao.fraunhofer.de",
           "resolvedDoc": {
               "document": {},
               "endpoints": [
                   {
                       "vcUri": "https://tspa.train1.xfsc.dev/tspa-service/tspa/v1/alice.trust.train1.xfsc.dev/vc/trust-list",
                       "tlUri": "http://tspa.train1.xfsc.dev/tspa-service/tspa/v1/alice.trust.train1.xfsc.dev/trust-list",
                       "trustList": null,
                       "vcVerified": ` + vcVerified + `
                   }
               ],
               "didVerified": ` + didVerified + `
           },
           "error": null
       }
   ]
}`

	return resp
}
