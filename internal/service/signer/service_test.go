// nolint:gosec,revive
package signer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	goasigner "github.com/eclipse-xfsc/crypto-provider-service/gen/signer"
	"github.com/eclipse-xfsc/crypto-provider-service/internal/service/signer"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/engine/core"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/engine/core/types"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/golib/errors"
)

var docLoader *ld.CachingDocumentLoader
var plugins []string
var wg sync.WaitGroup

func TestMain(m *testing.M) {
	c := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
			MaxIdleConns:        1,
			MaxIdleConnsPerHost: 1,
			TLSHandshakeTimeout: 5 * time.Second,
			IdleConnTimeout:     60 * time.Second,
		},
		Timeout: 10 * time.Second,
	}

	if docLoader == nil {
		docLoader = ld.NewCachingDocumentLoader(ld.NewDefaultDocumentLoader(c))
	}

	_, filename, _, _ := runtime.Caller(0)
	exPath := filepath.Dir(filename)
	pluginPath := path.Join(exPath, "../../../.engines")

	plugins = make([]string, 0)
	plugins = append(plugins, path.Join(pluginPath, ".local/local-provider.so"))
	plugins = append(plugins, path.Join(pluginPath, ".vault/hashicorp-vault-provider.so"))

	os.Setenv("VAULT_ADRESS", "http://localhost:8200")
	os.Setenv("VAULT_TOKEN", "test")
	os.Exit(m.Run())
}

func TestService_Namespaces(t *testing.T) {

	for _, v := range plugins {

		cryptoProvider := core.CreateCryptoEngine(v)

		t.Run("cryptoprovider fails to return namespaces", func(t *testing.T) {
			cryptoProvider.DestroyCryptoContext(types.CryptoContext{Namespace: "transit"})
			svc := signer.New(cryptoProvider, []signer.Verifier{}, []string{}, docLoader, zap.NewNop(), "", "", "", &wg, "")
			namespaces, err := svc.Namespaces(context.Background())
			assert.NotNil(t, namespaces)
			assert.Nil(t, err)
			assert.Empty(t, namespaces)
		})

		t.Run("cryptoprovider returns namespaces successfully", func(t *testing.T) {
			ctx1 := types.CryptoContext{Namespace: "transit", Group: "1", Context: context.Background()}
			ctx2 := types.CryptoContext{Namespace: "hello", Group: "1", Context: context.Background()}
			err := cryptoProvider.CreateCryptoContext(ctx1)

			assert.Nil(t, err)

			err = cryptoProvider.CreateCryptoContext(ctx2)

			assert.Nil(t, err)

			svc := signer.New(cryptoProvider, []signer.Verifier{}, []string{}, docLoader, zap.NewNop(), "", "", "", &wg, "")
			namespaces, err := svc.Namespaces(context.Background())
			assert.NoError(t, err)
			assert.NotNil(t, namespaces)
			slices.Sort(namespaces)
			assert.Equal(t, namespaces, []string{"hello/1", "transit/1"})
			cryptoProvider.DestroyCryptoContext(ctx1)
			cryptoProvider.DestroyCryptoContext(ctx2)
		})
	}
}

func TestService_NamespaceKeys(t *testing.T) {
	for _, v := range plugins {

		cryptoProvider := core.CreateCryptoEngine(v)

		t.Run("error while fetching keys", func(t *testing.T) {
			svc := signer.New(cryptoProvider, []signer.Verifier{}, []string{}, docLoader, zap.NewNop(), "", "", "", &wg, "")
			keys, err := svc.NamespaceKeys(context.Background(), &goasigner.NamespaceKeysRequest{})
			assert.Nil(t, keys)
			assert.NotNil(t, err)
		})

		t.Run("no keys found in namespace", func(t *testing.T) {
			ctx := types.CryptoContext{Namespace: "transit", Group: "8", Context: context.Background()}
			err := cryptoProvider.CreateCryptoContext(ctx)
			assert.Nil(t, err)
			svc := signer.New(cryptoProvider, []signer.Verifier{}, []string{}, docLoader, zap.NewNop(), "", "", "", &wg, "")
			keys, err := svc.NamespaceKeys(context.Background(), &goasigner.NamespaceKeysRequest{Namespace: "transit", XGroup: "8"})
			assert.Empty(t, keys)
			assert.Nil(t, err)
			cryptoProvider.DestroyCryptoContext(ctx)
		})

		t.Run("keys are retrieved successfully", func(t *testing.T) {
			ctx := types.CryptoContext{Namespace: "1", Group: "x", Context: context.Background()}
			err := cryptoProvider.CreateCryptoContext(ctx)

			assert.Nil(t, err)

			err = cryptoProvider.GenerateKey(types.CryptoKeyParameter{
				Identifier: types.CryptoIdentifier{
					KeyId:         "key1",
					CryptoContext: ctx,
				},
				KeyType: types.Ecdsap256,
			})

			assert.Nil(t, err)

			err = cryptoProvider.GenerateKey(types.CryptoKeyParameter{
				Identifier: types.CryptoIdentifier{
					KeyId:         "key3",
					CryptoContext: ctx,
				},
				KeyType: types.Ecdsap256,
			})

			assert.Nil(t, err)

			svc := signer.New(cryptoProvider, []signer.Verifier{}, []string{}, docLoader, zap.NewNop(), "", "", "", &wg, "")
			keys, err := svc.NamespaceKeys(context.Background(), &goasigner.NamespaceKeysRequest{Namespace: ctx.Namespace, XGroup: ctx.Group})
			assert.NoError(t, err)
			assert.Contains(t, keys, "key1", "key3")
			cryptoProvider.DestroyCryptoContext(ctx)
		})
	}
}

func TestService_VerificationMethod(t *testing.T) {
	for _, v := range plugins {

		cryptoProvider := core.CreateCryptoEngine(v)

		t.Run("signer returns error when getting key", func(t *testing.T) {
			svc := signer.New(cryptoProvider, []signer.Verifier{}, []string{}, docLoader, zap.NewNop(), "", "", "", &wg, "")
			result, err := svc.VerificationMethod(context.Background(), &goasigner.VerificationMethodRequest{Key: "key1"})
			assert.Nil(t, result)
			assert.Error(t, err)
		})

		t.Run("signer returns ecdsa-p256 key successfully", func(t *testing.T) {

			ctx := types.CryptoContext{Namespace: "2", Context: context.Background()}
			err := cryptoProvider.CreateCryptoContext(ctx)

			assert.Nil(t, err)

			err = cryptoProvider.GenerateKey(types.CryptoKeyParameter{
				Identifier: types.CryptoIdentifier{
					KeyId:         "key18",
					CryptoContext: ctx,
				},
				KeyType: types.Ecdsap256,
			})

			assert.Nil(t, err)

			svc := signer.New(cryptoProvider, []signer.Verifier{}, []string{"ecdsa-p256"}, docLoader, zap.NewNop(), "", "", "", &wg, "")
			result, err := svc.VerificationMethod(context.Background(), &goasigner.VerificationMethodRequest{Did: "did:web:example.com", Key: "key18", Namespace: ctx.Namespace, Group: ctx.Group})
			assert.NotNil(t, result)
			assert.NoError(t, err)

			assert.Equal(t, "did:web:example.com#key18", result.ID)
			assert.Equal(t, "did:web:example.com", result.Controller)
			assert.Equal(t, "JsonWebKey2020", result.Type)
			key := result.PublicKeyJwk.(jwk.Key)
			assert.NotNil(t, key)
			var rawKey interface{}
			err = key.Raw(&rawKey)
			assert.Nil(t, err)
			assert.IsType(t, (*ecdsa.PublicKey)(nil), rawKey)
			cryptoProvider.DestroyCryptoContext(ctx)
		})
	}
}

func TestService_VerificationMethods(t *testing.T) {
	for _, v := range plugins {

		cryptoProvider := core.CreateCryptoEngine(v)

		t.Run("signer returns error when getting verification methods", func(t *testing.T) {
			svc := signer.New(cryptoProvider, []signer.Verifier{}, []string{}, docLoader, zap.NewNop(), "", "", "", &wg, "")
			result, err := svc.VerificationMethods(context.Background(), &goasigner.VerificationMethodsRequest{Namespace: "unknown"})
			assert.Nil(t, result)
			assert.Error(t, err)
			e, ok := err.(*errors.Error)
			assert.True(t, ok)
			assert.Equal(t, errors.Internal, e.Kind)
		})

		t.Run("signer return empty list if vault has no keys", func(t *testing.T) {
			ctx := types.CryptoContext{
				Namespace: "nm",
				Group:     "test",
				Context:   context.Background(),
				Engine:    "transit",
			}
			cryptoProvider.CreateCryptoContext(ctx)

			svc := signer.New(cryptoProvider, []signer.Verifier{}, []string{}, docLoader, zap.NewNop(), "", "", "", &wg, "")
			result, err := svc.VerificationMethods(context.Background(), &goasigner.VerificationMethodsRequest{
				Did:       "did:web:example.com",
				Namespace: "nm",
				Group:     "test",
				Engine:    "transit",
			})
			assert.Empty(t, result)
			assert.NoError(t, err)
			cryptoProvider.DestroyCryptoContext(ctx)
		})

		t.Run("signer returns one ecdsa-p256 key successfully", func(t *testing.T) {

			ctx := types.CryptoContext{
				Namespace: "nm",
				Context:   context.Background(),
			}
			cryptoProvider.CreateCryptoContext(ctx)

			id := types.CryptoKeyParameter{
				Identifier: types.CryptoIdentifier{
					KeyId:         "key1",
					CryptoContext: ctx,
				},
				KeyType: types.Ecdsap256,
			}

			cryptoProvider.GenerateKey(id)

			svc := signer.New(cryptoProvider, []signer.Verifier{}, []string{"ecdsa-p256"}, docLoader, zap.NewNop(), "", "", "", &wg, "")
			result, err := svc.VerificationMethods(context.Background(), &goasigner.VerificationMethodsRequest{
				Did:       "did:web:example.com",
				Namespace: "nm",
			})
			assert.NotNil(t, result)
			assert.NoError(t, err)

			assert.Len(t, result, 1)
			assert.Equal(t, "did:web:example.com#key1", result[0].ID)
			assert.Equal(t, "did:web:example.com", result[0].Controller)
			assert.Equal(t, "JsonWebKey2020", result[0].Type)
			assert.NotNil(t, result[0].PublicKeyJwk)

			key := result[0].PublicKeyJwk.(jwk.Key)
			assert.NotNil(t, key)
			var rawKey interface{}
			err = key.Raw(&rawKey)
			assert.Nil(t, err)
			assert.IsType(t, (*ecdsa.PublicKey)(nil), rawKey)
			cryptoProvider.DestroyCryptoContext(ctx)
		})

		t.Run("signer returns two key successfully", func(t *testing.T) {

			ctx := types.CryptoContext{
				Namespace: "pm",
				Context:   context.Background(),
			}
			cryptoProvider.CreateCryptoContext(ctx)

			id := types.CryptoKeyParameter{
				Identifier: types.CryptoIdentifier{
					KeyId:         "key2",
					CryptoContext: ctx,
				},
				KeyType: types.Ecdsap256,
			}

			id2 := types.CryptoKeyParameter{
				Identifier: types.CryptoIdentifier{
					KeyId:         "key1",
					CryptoContext: ctx,
				},
				KeyType: types.Rsa4096,
			}

			cryptoProvider.GenerateKey(id)
			cryptoProvider.GenerateKey(id2)

			svc := signer.New(cryptoProvider, []signer.Verifier{}, []string{string(types.Rsa4096), string(types.Ecdsap256)}, docLoader, zap.NewNop(), "", "", "", &wg, "")
			result, err := svc.VerificationMethods(context.Background(), &goasigner.VerificationMethodsRequest{
				Did:       "did:web:example.com",
				Namespace: "pm",
			})
			assert.NotNil(t, result)
			assert.NoError(t, err)
			assert.Len(t, result, 2)

			assert.Equal(t, "did:web:example.com#key1", result[0].ID)
			assert.Equal(t, "did:web:example.com", result[0].Controller)
			assert.Equal(t, "JsonWebKey2020", result[0].Type)
			assert.NotNil(t, result[0].PublicKeyJwk)

			key := result[0].PublicKeyJwk.(jwk.Key)
			assert.NotNil(t, key)
			var rawKey interface{}
			err = key.Raw(&rawKey)
			assert.Nil(t, err)
			assert.IsType(t, (*rsa.PublicKey)(nil), rawKey)

			assert.Equal(t, "did:web:example.com#key2", result[1].ID)
			assert.Equal(t, "JsonWebKey2020", result[1].Type)
			assert.NotNil(t, result[1].PublicKeyJwk)

			key2 := result[1].PublicKeyJwk.(jwk.Key)
			assert.NotNil(t, key2)
			var rawKey2 interface{}
			err = key2.Raw(&rawKey2)
			assert.Nil(t, err)
			assert.IsType(t, (*ecdsa.PublicKey)(nil), rawKey2)
			cryptoProvider.DestroyCryptoContext(ctx)
		})
	}
}

func TestService_JwkPublicKey(t *testing.T) {
	for _, v := range plugins {

		cryptoProvider := core.CreateCryptoEngine(v)

		t.Run("signer returns error when getting key", func(t *testing.T) {
			svc := signer.New(cryptoProvider, []signer.Verifier{}, []string{}, docLoader, zap.NewNop(), "", "", "", &wg, "")
			result, err := svc.JwkPublicKey(
				context.Background(),
				&goasigner.JwkPublicKeyRequest{Namespace: "transit", Key: "key1"},
			)
			assert.Nil(t, result)
			assert.Error(t, err)
			e, ok := err.(*errors.Error)
			assert.True(t, ok)
			assert.Equal(t, errors.NotFound, e.Kind)
		})

		t.Run("signer returns ecdsa-p256 key successfully", func(t *testing.T) {
			ctx := types.CryptoContext{
				Namespace: "transit",
				Context:   context.Background(),
			}
			cryptoProvider.CreateCryptoContext(ctx)

			id := types.CryptoKeyParameter{
				Identifier: types.CryptoIdentifier{
					KeyId:         "key1",
					CryptoContext: ctx,
				},
				KeyType: types.Ecdsap256,
			}

			cryptoProvider.GenerateKey(id)

			svc := signer.New(cryptoProvider, []signer.Verifier{}, []string{"ecdsa-p256"}, docLoader, zap.NewNop(), "", "", "", &wg, "")
			result, err := svc.JwkPublicKey(
				context.Background(),
				&goasigner.JwkPublicKeyRequest{Namespace: "transit", Key: "key1"},
			)
			key := result.(jwk.Key)
			assert.NotNil(t, key)
			assert.NoError(t, err)

			var rawKey interface{}
			err = key.Raw(&rawKey)
			assert.Nil(t, err)
			assert.IsType(t, (*ecdsa.PublicKey)(nil), rawKey)
			cryptoProvider.DestroyCryptoContext(ctx)
		})
	}
}

func TestService_CredentialProof(t *testing.T) {

	for _, v := range plugins {

		cryptoProvider := core.CreateCryptoEngine(v)

		ctx := types.CryptoContext{
			Namespace: "transit",
			Context:   context.Background(),
		}
		cryptoProvider.CreateCryptoContext(ctx)

		cryptoProvider.GenerateKey(types.CryptoKeyParameter{
			Identifier: types.CryptoIdentifier{
				KeyId:         "exotickey",
				CryptoContext: ctx,
			},
			KeyType: types.Aes256GCM,
		})

		cryptoProvider.GenerateKey(types.CryptoKeyParameter{
			Identifier: types.CryptoIdentifier{
				KeyId:         "edkey",
				CryptoContext: ctx,
			},
			KeyType: types.Ed25519,
		})

		cryptoProvider.GenerateKey(types.CryptoKeyParameter{
			Identifier: types.CryptoIdentifier{
				KeyId:         "eckey",
				CryptoContext: ctx,
			},
			KeyType: types.Ecdsap256,
		})

		cryptoProvider.GenerateKey(types.CryptoKeyParameter{
			Identifier: types.CryptoIdentifier{
				KeyId:         "rsakey",
				CryptoContext: ctx,
			},
			KeyType: types.Ecdsap256,
		})

		tests := []struct {
			name          string
			signer        types.CryptoProvider
			supportedKeys []string

			namespace  string
			keyname    string
			credential []byte

			errkind errors.Kind
			errtext string

			contexts                []string
			types                   []string
			subject                 []verifiable.Subject
			issuer                  verifiable.Issuer
			proofPurpose            string
			proofType               string
			proofVerificationMethod string
		}{
			{
				name:       "invalid credential",
				credential: []byte(invalidCredential),
				errkind:    errors.BadRequest,
				errtext:    "credential type of unknown structure",
			},
			{
				name:       "invalid credential contexts",
				credential: []byte(invalidCredentialContexts),
				errkind:    errors.BadRequest,
				errtext:    "Dereferencing a URL did not result in a valid JSON-LD context",
			},
			{
				name:       "non-existing credential contexts",
				credential: []byte(nonExistingCredentialContexts),
				errkind:    errors.BadRequest,
				errtext:    "Dereferencing a URL did not result in a valid JSON-LD context",
			},
			{
				name:       "credential with invalid subject id",
				credential: []byte(credentialWithInvalidSubjectID),
				errkind:    errors.BadRequest,
				errtext:    "invalid subject id: must be URI",
			},
			{
				name:       "valid credential but signer cannot find key",
				namespace:  "transit",
				keyname:    "keyyyyyyyy",
				credential: []byte(validCredential),
				signer:     cryptoProvider,
				errkind:    errors.NotFound,
				errtext:    "failed to fetch key",
			},
			{
				name:       "valid credential but signer returns unsupported key type",
				namespace:  "transit",
				keyname:    "exotickey",
				credential: []byte(validCredential),
				signer:     cryptoProvider,
				errkind:    errors.Unknown,
				errtext:    "unsupported key type",
			},
			{
				name:          "valid credential and signer key type ed25519",
				supportedKeys: []string{string(types.Ed25519)},
				namespace:     "transit",
				keyname:       "edkey",
				credential:    []byte(validCredential),
				signer:        cryptoProvider,

				// expected attributes the VC must have
				contexts:                []string{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1", "https://schema.org"},
				subject:                 []verifiable.Subject{{ID: "", CustomFields: verifiable.CustomFields{"testdata": map[string]interface{}{"hello": "world"}}}},
				issuer:                  verifiable.Issuer{ID: "https://example.com"},
				types:                   []string{verifiable.VCType},
				proofPurpose:            "assertionMethod",
				proofType:               "JsonWebSignature2020",
				proofVerificationMethod: "https://example.com#edkey",
			},
			{
				name:          "valid credential and signer key type ecdsa-p256",
				supportedKeys: []string{string(types.Ecdsap256)},
				namespace:     "transit",
				keyname:       "eckey",
				credential:    []byte(validCredential),
				signer:        cryptoProvider,

				// expected attributes the VC must have
				contexts:                []string{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1", "https://schema.org"},
				subject:                 []verifiable.Subject{{ID: "", CustomFields: verifiable.CustomFields{"testdata": map[string]interface{}{"hello": "world"}}}},
				issuer:                  verifiable.Issuer{ID: "https://example.com"},
				types:                   []string{verifiable.VCType},
				proofPurpose:            "assertionMethod",
				proofType:               "JsonWebSignature2020",
				proofVerificationMethod: "https://example.com#eckey",
			},
			{
				name:          "valid credential and signer key type ecdsa-p256",
				supportedKeys: []string{string(types.Ecdsap256)},
				namespace:     "transit",
				keyname:       "eckey",
				credential:    []byte(validCredential),
				signer:        cryptoProvider,

				// expected attributes the VC must have
				contexts:                []string{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1", "https://schema.org"},
				subject:                 []verifiable.Subject{{ID: "", CustomFields: verifiable.CustomFields{"testdata": map[string]interface{}{"hello": "world"}}}},
				issuer:                  verifiable.Issuer{ID: "https://example.com"},
				types:                   []string{verifiable.VCType},
				proofPurpose:            "assertionMethod",
				proofType:               "JsonWebSignature2020",
				proofVerificationMethod: "https://example.com#eckey",
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				svc := signer.New(test.signer, []signer.Verifier{}, test.supportedKeys, docLoader, zap.NewNop(), "", "", "", &wg, "")

				var cred interface{}
				err := json.Unmarshal(test.credential, &cred)
				assert.NoError(t, err)

				res, err := svc.CredentialProof(context.Background(), &goasigner.CredentialProofRequest{
					Namespace:  test.namespace,
					Key:        test.keyname,
					Credential: cred,
					Format:     "ldp_vc",
				})
				if err != nil {
					assert.Nil(t, res)
					require.NotEmpty(t, test.errtext, "error is not expected, but got: %v ", err)
					assert.Contains(t, err.Error(), test.errtext)
					if e, ok := err.(*errors.Error); ok {
						assert.Equal(t, test.errkind, e.Kind)
					}
				} else {
					assert.Empty(t, test.errtext)
					assert.NotNil(t, res)

					vc, ok := res.(*verifiable.Credential)
					assert.True(t, ok)

					assert.Equal(t, test.contexts, vc.Context)
					assert.Equal(t, test.subject, vc.Subject)
					assert.Equal(t, test.issuer, vc.Issuer)
					assert.Equal(t, test.types, vc.Types)
					assert.Equal(t, test.proofPurpose, vc.Proofs[0]["proofPurpose"])
					assert.Equal(t, test.proofType, vc.Proofs[0]["type"])
					assert.Equal(t, test.proofVerificationMethod, vc.Proofs[0]["verificationMethod"])
					assert.NotEmpty(t, vc.Proofs[0]["jws"])
				}
			})

			time.Sleep(2 * time.Second)
		}
		cryptoProvider.DestroyCryptoContext(ctx)
	}
}

func TestService_PresentationProof(t *testing.T) {
	for _, v := range plugins {

		cryptoProvider := core.CreateCryptoEngine(v)

		ctx := types.CryptoContext{
			Namespace: "transit",
			Context:   context.Background(),
		}
		cryptoProvider.CreateCryptoContext(ctx)

		cryptoProvider.GenerateKey(types.CryptoKeyParameter{
			Identifier: types.CryptoIdentifier{
				KeyId:         "exotickey",
				CryptoContext: ctx,
			},
			KeyType: types.Aes256GCM,
		})

		cryptoProvider.GenerateKey(types.CryptoKeyParameter{
			Identifier: types.CryptoIdentifier{
				KeyId:         "edkey",
				CryptoContext: ctx,
			},
			KeyType: types.Ed25519,
		})

		cryptoProvider.GenerateKey(types.CryptoKeyParameter{
			Identifier: types.CryptoIdentifier{
				KeyId:         "eckey",
				CryptoContext: ctx,
			},
			KeyType: types.Ecdsap256,
		})

		cryptoProvider.GenerateKey(types.CryptoKeyParameter{
			Identifier: types.CryptoIdentifier{
				KeyId:         "rsakey",
				CryptoContext: ctx,
			},
			KeyType: types.Ecdsap256,
		})

		tests := []struct {
			name          string
			signer        types.CryptoProvider
			supportedKeys []string

			issuer       string
			namespace    string
			keyname      string
			presentation []byte

			errkind errors.Kind
			errtext string

			contexts                []string
			types                   []string
			proofPurpose            string
			proofType               string
			proofVerificationMethod string
		}{
			{
				name:         "invalid verifiable presentation",
				presentation: []byte(invalidPresentation),
				errkind:      errors.BadRequest,
				errtext:      "verifiable presentation is not valid",
			},
			{
				name:         "invalid presentation contexts",
				presentation: []byte(invalidPresentationContexts),
				errkind:      errors.BadRequest,
				errtext:      "verifiable presentation is not valid",
			},
			{
				name:         "non-existing presentation contexts",
				presentation: []byte(nonExistingPresentationContexts),
				errkind:      errors.BadRequest,
				errtext:      "Dereferencing a URL did not result in a valid JSON-LD context",
			},
			{
				name:         "presentation with missing credential context",
				presentation: []byte(presentationWithMissingCredentialContext),
				errkind:      errors.BadRequest,
				errtext:      "JSON-LD doc has different structure after compaction",
			},
			{
				name:         "valid presentation but signer cannot find key",
				namespace:    "transit",
				keyname:      "keyyyyyyyy",
				presentation: []byte(validPresentation),
				signer:       cryptoProvider,
				errkind:      errors.NotFound,
				errtext:      "failed to fetch key",
			},
			{
				name:         "valid presentation but signer returns unsupported key type",
				namespace:    "transit",
				keyname:      "exotickey",
				presentation: []byte(validPresentation),
				signer:       cryptoProvider,
				errkind:      errors.Unknown,
				errtext:      "unsupported key type",
			},
			{
				name:          "valid presentation and signer key type ed25519",
				supportedKeys: []string{"ed25519"},
				issuer:        "https://example.com",
				namespace:     "transit",
				keyname:       "edkey",
				presentation:  []byte(validPresentation),
				signer:        cryptoProvider,

				// expected attributes the VC must have
				contexts:                []string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"},
				types:                   []string{verifiable.VPType},
				proofPurpose:            "assertionMethod",
				proofType:               "JsonWebSignature2020",
				proofVerificationMethod: "https://example.com#edkey",
			},
			{
				name:          "valid presentation and signer key type ecdsa-p256",
				supportedKeys: []string{"ed25519", "ecdsa-p256"},
				issuer:        "https://example.com",
				namespace:     "transit",
				keyname:       "eckey",
				presentation:  []byte(validPresentation),
				signer:        cryptoProvider,

				// expected attributes the VC must have
				contexts:                []string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"},
				types:                   []string{verifiable.VPType},
				proofPurpose:            "assertionMethod",
				proofType:               "JsonWebSignature2020",
				proofVerificationMethod: "https://example.com#eckey",
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				svc := signer.New(test.signer, []signer.Verifier{}, test.supportedKeys, docLoader, zap.NewNop(), "", "", "", &wg, "")

				var pres interface{}
				err := json.Unmarshal(test.presentation, &pres)
				assert.NoError(t, err)

				res, err := svc.PresentationProof(context.Background(), &goasigner.PresentationProofRequest{
					Issuer:       &test.issuer,
					Namespace:    test.namespace,
					Key:          test.keyname,
					Presentation: pres,
					Format:       "ldp_vc",
				})
				if err != nil {
					assert.Nil(t, res)
					require.NotEmpty(t, test.errtext, "error is not expected, but got: %v")
					assert.Contains(t, err.Error(), test.errtext)
					if e, ok := err.(*errors.Error); ok {
						assert.Equal(t, test.errkind, e.Kind)
					}
					return
				}

				require.NotNil(t, res)
				vp, ok := res.(*verifiable.Presentation)
				assert.True(t, ok)

				assert.Equal(t, test.contexts, vp.Context)
				assert.Equal(t, test.types, vp.Type)
				assert.Equal(t, test.proofPurpose, vp.Proofs[0]["proofPurpose"])
				assert.Equal(t, test.proofType, vp.Proofs[0]["type"])
				assert.Equal(t, test.proofVerificationMethod, vp.Proofs[0]["verificationMethod"])
				assert.NotEmpty(t, vp.Proofs[0]["jws"])
			})

			time.Sleep(2 * time.Second)
		}
		cryptoProvider.DestroyCryptoContext(ctx)
	}
}

func TestService_CreateCredential(t *testing.T) {
	for _, v := range plugins {

		cryptoProvider := core.CreateCryptoEngine(v)

		ctx := types.CryptoContext{
			Namespace: "transit",
			Context:   context.Background(),
		}
		cryptoProvider.CreateCryptoContext(ctx)

		cryptoProvider.GenerateKey(types.CryptoKeyParameter{
			Identifier: types.CryptoIdentifier{
				KeyId:         "edkey",
				CryptoContext: ctx,
			},
			KeyType: types.Ed25519,
		})

		cryptoProvider.GenerateKey(types.CryptoKeyParameter{
			Identifier: types.CryptoIdentifier{
				KeyId:         "eckey",
				CryptoContext: ctx,
			},
			KeyType: types.Ecdsap256,
		})

		tests := []struct {
			name          string
			signer        types.CryptoProvider
			supportedKeys []string

			issuer            string
			namespace         string
			keyname           string
			credentialSubject map[string]interface{}

			errkind errors.Kind
			errtext string

			contexts                []string
			types                   []string
			proofPurpose            string
			proofType               string
			proofVerificationMethod string
			wantedCredentialSubject verifiable.Subject
		}{
			{
				name:    "missing credential subject",
				errtext: "invalid credential subject",
				errkind: errors.BadRequest,
			},
			{
				name:              "invalid credential subject id",
				credentialSubject: map[string]interface{}{"id": "invalid credential subject id"},
				errtext:           "invalid credential subject",
				errkind:           errors.BadRequest,
			},
			{
				name:              "valid credential subject, but error finding signing key",
				supportedKeys:     []string{"ed25519", "ecdsa-p256"},
				issuer:            "https://example.com",
				namespace:         "transit",
				keyname:           "keyyyyyyyyyyy",
				credentialSubject: map[string]interface{}{"id": "https://example.com"},
				signer:            cryptoProvider,
				errtext:           "error during signing",
				errkind:           errors.Internal,
			},
			{
				name:              "valid credential subject and signing is successful",
				supportedKeys:     []string{"ed25519", "ecdsa-p256"},
				issuer:            "https://example.com",
				namespace:         "transit",
				keyname:           "eckey",
				credentialSubject: map[string]interface{}{"id": "https://example.com"},
				signer:            cryptoProvider,
				// expected attributes the VC must have
				contexts: []string{
					"https://www.w3.org/2018/credentials/v1",
					"https://w3id.org/security/suites/jws-2020/v1",
					"https://schema.org",
				},
				types:                   []string{verifiable.VCType},
				proofPurpose:            "assertionMethod",
				proofType:               "JsonWebSignature2020",
				proofVerificationMethod: "https://example.com#eckey",
				wantedCredentialSubject: verifiable.Subject{
					ID:           "https://example.com",
					CustomFields: map[string]interface{}{},
				},
			},
			{
				name:              "valid credential with multiple claims and signing is successful",
				supportedKeys:     []string{"ed25519", "ecdsa-p256"},
				issuer:            "https://example.com",
				namespace:         "transit",
				keyname:           "edkey",
				credentialSubject: map[string]interface{}{"id": "https://example.com", "email": "test@mymail.com"},
				signer:            cryptoProvider,
				// expected attributes the VC must have
				contexts: []string{
					"https://www.w3.org/2018/credentials/v1",
					"https://w3id.org/security/suites/jws-2020/v1",
					"https://schema.org",
				},
				types:                   []string{verifiable.VCType},
				proofPurpose:            "assertionMethod",
				proofType:               "JsonWebSignature2020",
				proofVerificationMethod: "https://example.com#edkey",
				wantedCredentialSubject: verifiable.Subject{
					ID: "https://example.com",
					CustomFields: map[string]interface{}{
						"email": "test@mymail.com",
					},
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				signer := signer.New(test.signer, []signer.Verifier{}, test.supportedKeys, docLoader, zap.NewNop(), "", "", "", &wg, "")

				req := &goasigner.CreateCredentialRequest{
					Issuer:            &test.issuer,
					Namespace:         test.namespace,
					Key:               test.keyname,
					CredentialSubject: test.credentialSubject,
					Format:            "ldp_vc",
				}

				credential, err := signer.CreateCredential(context.Background(), req)
				if err != nil {
					require.NotEmpty(t, test.errtext, "received error, but test case has no error: %v", err)
					assert.Contains(t, err.Error(), test.errtext)
					if e, ok := err.(*errors.Error); ok {
						assert.Equal(t, test.errkind, e.Kind)
					}
					assert.Nil(t, credential)
				} else {
					require.Empty(t, test.errtext, "test case expects error, but got none")
					assert.NotNil(t, credential)

					vc, ok := credential.(*verifiable.Credential)
					assert.True(t, ok)
					slices.Sort(test.contexts)
					slices.Sort(vc.Context)
					assert.Equal(t, test.contexts, vc.Context)
					assert.Equal(t, test.types, vc.Types)
					assert.Equal(t, test.proofPurpose, vc.Proofs[0]["proofPurpose"])
					assert.Equal(t, test.proofType, vc.Proofs[0]["type"])
					assert.Equal(t, test.proofVerificationMethod, vc.Proofs[0]["verificationMethod"])
					assert.NotEmpty(t, vc.Proofs[0]["jws"])
					assert.Equal(t, test.wantedCredentialSubject, vc.Subject)
				}
			})

			time.Sleep(2 * time.Second)
		}
	}
}

func TestService_Sign(t *testing.T) {
	for _, v := range plugins {

		cryptoProvider := core.CreateCryptoEngine(v)

		ctx := types.CryptoContext{
			Namespace: "transit",
			Context:   context.Background(),
		}
		cryptoProvider.CreateCryptoContext(ctx)

		cryptoProvider.GenerateKey(types.CryptoKeyParameter{
			Identifier: types.CryptoIdentifier{
				KeyId:         "edkey",
				CryptoContext: ctx,
			},
			KeyType: types.Ed25519,
		})

		tests := []struct {
			name string
			// input
			signer types.CryptoProvider
			data   string
			// output
			signature string
			errkind   errors.Kind
			errtext   string
		}{
			{
				name:    "invalid encoding of data",
				data:    "not base64 encoded string",
				errtext: "cannot base64 decode data",
				errkind: errors.BadRequest,
			},
			{
				name:    "signing key not found",
				data:    base64.StdEncoding.EncodeToString([]byte("something")),
				signer:  cryptoProvider,
				errtext: "key not found",
				errkind: errors.NotFound,
			},
			{
				name:      "successful signing",
				data:      base64.StdEncoding.EncodeToString([]byte("something")),
				signer:    cryptoProvider,
				signature: base64.StdEncoding.EncodeToString([]byte("signature")),
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				svc := signer.New(test.signer, []signer.Verifier{}, nil, nil, zap.NewNop(), "", "", "", &wg, "")
				result, err := svc.Sign(context.Background(), &goasigner.SignRequest{
					Namespace: "transit",
					Key:       "edkey",
					Data:      test.data,
				})
				if err != nil {
					require.NotEmpty(t, test.errtext, "expected no error but got %s", err)
					require.Nil(t, result)
					assert.ErrorContains(t, err, test.errtext)
					e, ok := err.(*errors.Error)
					require.True(t, ok)
					assert.Equal(t, test.errkind, e.Kind)
					return
				}

				//require.Empty(t, test.errtext, "got no error, but expected: %s", test.errtext)
				require.NotNil(t, result)
				assert.NotEmpty(t, result.Signature)
			})
		}
	}
}

// ---------- Verifiable Credentials ---------- //

//nolint:gosec
var validCredential = `{
  "@context": [
	"https://www.w3.org/2018/credentials/v1",
	"https://w3id.org/security/suites/jws-2020/v1",
	"https://schema.org"
  ],
  "credentialSubject": {
	"testdata": {"hello":"world"}
  },
  "issuanceDate": "2022-06-02T17:24:05.032533+03:00",
  "issuer": "https://example.com",
  "type": "VerifiableCredential"
}`

//nolint:gosec
var provenanceCredential = `{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
        "https://schema.org"
    ],
    "credentialSubject": {
        "!disclose:testdata": {
            "!disclose:hello": "world",
            "testXY": "1234"
        },
        "provenanceProof": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/suites/jws-2020/v1",
                "https://schema.org"
            ],
            "credentialSubject": {
                "!disclose:testdata": {
                    "!disclose:hello": "world",
                    "testXY": "1234"
                }
            },
            "issuanceDate": "2024-02-05T19:10:28.871407+01:00",
            "issuer": "did:jwk:eyJjcnYiOiJQLTI1NiIsImtpZCI6InRlc3QiLCJrdHkiOiJFQyIsIngiOiJaZ1Z3UXdyUC1yTy1OM25mbHZsVUpLZjhlLTJoeWhSZmdSekotTkxlTWFNIiwieSI6IjlVWEl5bE1PX0NaZ0M0aGxHN1hGQVU0b1dYSVkyZkRMT0RSalRqSWZEOGMifQ==",
            "proof": {
                "created": "2024-02-05T19:10:28.924861+01:00",
                "jws": "eyJhbGciOiIiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..MEYCIQDoLgKHlEsl7LyJS-TiRPusTsTNv0LGGYp02wZA-gddKQIhAKbLMGnltpI3AZNwTel0CqPLlAooIwYvSPEJOamB6K6Z",
                "proofPurpose": "assertionMethod",
                "type": "JsonWebSignature2020",
                "verificationMethod": "did:jwk:eyJjcnYiOiJQLTI1NiIsImtpZCI6InRlc3QiLCJrdHkiOiJFQyIsIngiOiJaZ1Z3UXdyUC1yTy1OM25mbHZsVUpLZjhlLTJoeWhSZmdSekotTkxlTWFNIiwieSI6IjlVWEl5bE1PX0NaZ0M0aGxHN1hGQVU0b1dYSVkyZkRMT0RSalRqSWZEOGMifQ==#test"
            },
            "type": "VerifiableCredential"
        }
    },
    "issuanceDate": "2024-02-05T19:11:12.32895+01:00",
    "issuer": "did:jwk:eyJjcnYiOiJQLTI1NiIsImtpZCI6InRlc3QiLCJrdHkiOiJFQyIsIngiOiJaZ1Z3UXdyUC1yTy1OM25mbHZsVUpLZjhlLTJoeWhSZmdSekotTkxlTWFNIiwieSI6IjlVWEl5bE1PX0NaZ0M0aGxHN1hGQVU0b1dYSVkyZkRMT0RSalRqSWZEOGMifQ==",
    "proof": {
        "created": "2024-02-05T19:11:12.360685+01:00",
        "jws": "eyJhbGciOiIiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..MEUCIQD-hn0EXD21p2fFy-5ASL1pLlUAe0C7EtBb_vF75LQmVAIgEzf-lkaZ34BQnN8btS86SQQbsYCZegB2GjugeB0KdhQ",
        "proofPurpose": "assertionMethod",
        "type": "JsonWebSignature2020",
        "verificationMethod": "did:jwk:eyJjcnYiOiJQLTI1NiIsImtpZCI6InRlc3QiLCJrdHkiOiJFQyIsIngiOiJaZ1Z3UXdyUC1yTy1OM25mbHZsVUpLZjhlLTJoeWhSZmdSekotTkxlTWFNIiwieSI6IjlVWEl5bE1PX0NaZ0M0aGxHN1hGQVU0b1dYSVkyZkRMT0RSalRqSWZEOGMifQ==#test"
    },
    "type": "VerifiableCredential"
}`

var credentialWithInvalidSubjectID = `{
  "@context": [
	"https://www.w3.org/2018/credentials/v1",
	"https://w3id.org/security/suites/jws-2020/v1",
	"https://schema.org"
  ],
  "credentialSubject": {
	"id":"invalid",
	"testdata": {"hello":"world"}
  },
  "issuanceDate": "2022-06-02T17:24:05.032533+03:00",
  "issuer": "https://example.com",
  "type": "VerifiableCredential"
}`

//nolint:gosec
var invalidCredential = `{"invalid":"credential"}`

//nolint:gosec
var invalidCredentialContexts = `{
	"@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://adsklfhasefugaougyasdkfhaksjdhga.com/v1"
	],
	"credentialSubject": {
		"hello": "world"
	},
	"issuanceDate": "2022-06-02T17:24:05.032533+03:00",
	"issuer": "https://example.com",
	"type": "VerifiableCredential"
}`

//nolint:gosec
var nonExistingCredentialContexts = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://no-schema-here.com/credentials/context"
  ],
  "credentialSubject": {
    "hello": "world"
  },
  "issuanceDate": "2022-06-02T17:24:05.032533+03:00",
  "issuer": "https://example.com",
  "type": "VerifiableCredential"
}`

// ---------- Verifiable Presentations ---------- //

var validPresentation = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "did:123",
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1",
		"https://schema.org"
      ],
      "credentialSubject": {
        "allow": true,
        "taskID": "0123456789abcdef"
      },
      "issuanceDate": "2022-06-14T08:43:22.78309334Z",
      "issuer": "https://example.com",
      "type": "VerifiableCredential"
    },
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1",
		"https://schema.org"
      ],
      "credentialSubject": {
        "result": {
          "hello": "world"
        }
      },
      "issuanceDate": "2022-06-14T08:43:22.783102173Z",
      "issuer": "https://example.com",
      "type": "VerifiableCredential"
    }
  ]
}`

var invalidPresentation = `{"invalid":"presentation"}`

var invalidPresentationContexts = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v123"
  ],
  "id": "did:123",
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "credentialSubject": {
        "allow": true,
        "taskID": "0123456789abcdef"
      },
      "issuanceDate": "2022-06-14T08:43:22.78309334Z",
      "issuer": "https://example.com",
      "type": "VerifiableCredential"
    },
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "credentialSubject": {
        "result": {
          "hello": "world"
        }
      },
      "issuanceDate": "2022-06-14T08:43:22.783102173Z",
      "issuer": "https://example.com",
      "type": "VerifiableCredential"
    }
  ]
}`

var nonExistingPresentationContexts = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.akdjsghadkljghadlkgjhadlkgjha.org"
  ],
  "id": "did:123",
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "credentialSubject": {
        "allow": true,
        "taskID": "0123456789abcdef"
      },
      "issuanceDate": "2022-06-14T08:43:22.78309334Z",
      "issuer": "https://example.com",
      "type": "VerifiableCredential"
    },
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "credentialSubject": {
        "result": {
          "hello": "world"
        }
      },
      "issuanceDate": "2022-06-14T08:43:22.783102173Z",
      "issuer": "https://example.com",
      "type": "VerifiableCredential"
    }
  ]
}`

var presentationWithMissingCredentialContext = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "did:123",
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "credentialSubject": {
        "allow": true,
        "taskID": "0123456789abcdef"
      },
      "issuanceDate": "2022-06-14T08:43:22.78309334Z",
      "issuer": "https://example.com",
      "type": "VerifiableCredential"
    }
  ]
}`
