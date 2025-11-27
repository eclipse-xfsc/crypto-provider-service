package did

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/eclipse-xfsc/did-core/v2/types"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var did_resolver string
var initialized bool

func Initialize() {
	if initialized {
		return
	}
	viper.AutomaticEnv()
	did_resolver = viper.GetString("DID_RESOLVER")
}

type didResolution struct {
	Document interface{} `json:"didDocument"`
}

func ParseDidDocument(didJson string) (*types.DidDocument, error) {
	var didDoc types.DidDocument
	err := json.Unmarshal([]byte(didJson), &didDoc)

	if err != nil {
		return nil, err
	}

	return &didDoc, nil
}

func ToDidWeb(rawURL string, dockerAware bool) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("ungültige URL: %w", err)
	}

	host := parsedURL.Host
	if host == "" {
		// Fallback für reine Hoststrings wie "127.0.0.1:8080"
		host = rawURL
	}

	// Sonderbehandlung für docker-aware mode
	if dockerAware {
		if strings.HasPrefix(host, "127.0.0.1") || strings.HasPrefix(host, "localhost") {
			// Versuche Port zu erhalten (falls vorhanden)
			parts := strings.Split(host, ":")
			if len(parts) == 2 {
				host = "host.docker.internal:" + parts[1]
			} else {
				host = "host.docker.internal"
			}
		}
	}

	// DID:web verlangt Encoding von ":" → "%3A"
	didSafeHost := strings.ReplaceAll(host, ":", "%3A")

	didWeb := fmt.Sprintf("did:web:%s", didSafeHost)
	return didWeb, nil
}

func extractHttpBody(reader io.ReadCloser) string {
	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		logrus.Fatal(err)
	}
	bodyString := string(bodyBytes)
	return bodyString
}

func resolveWithResolver(did string) ([]byte, error) {
	req, err := http.NewRequest("GET", did_resolver+"/1.0/identifiers/"+did, nil)
	if err != nil {
		return nil, err
	}

	request := req.WithContext(context.Background())

	resp, err := http.DefaultClient.Do(request)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() // nolint:errcheck

	v := extractHttpBody(resp.Body)
	if err != nil {
		return nil, err
	}
	var didResolve didResolution
	err = json.Unmarshal([]byte(v), &didResolve)

	if err != nil {
		return nil, err
	}

	s, err := json.Marshal(didResolve.Document)

	if err != nil {
		return nil, err
	}

	return s, nil
}

func resolveDidJwk(did string) (*types.DidDocument, error) {
	const prefix = "did:jwk:"
	if !strings.HasPrefix(did, prefix) {
		return nil, fmt.Errorf("not a did:jwk identifier: %s", did)
	}

	encoded := strings.TrimPrefix(did, prefix)

	// Base64URL-dekodieren (kein Padding!)
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to base64url-decode JWK: %w", err)
	}

	keyset, err := jwk.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	if keyset.Len() == 0 {
		return nil, errors.New("no keys found in JWK")
	}

	key, ok := keyset.Key(0)
	if !ok {
		return nil, errors.New("could not extract key from set")
	}

	vmID := did + "#0"
	doc := &types.DidDocument{
		Context: types.ContextValue{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		Id: did,
		VerificationMethod: []types.VerificationRelationShipEntry{
			types.VerificationRelationShipEntry{
				Key: &types.VerificationMethod{
					Id:           vmID,
					Type:         "JsonWebKey2020",
					Controller:   did,
					PublicKeyJwk: key,
				},
			},
		},
		Authentication: []types.VerificationRelationShipEntry{
			types.VerificationRelationShipEntry{
				Reference: &vmID,
			},
		},
		AssertionMethod: []types.VerificationRelationShipEntry{
			types.VerificationRelationShipEntry{
				Reference: &vmID,
			},
		},
		CapabilityInvocation: []types.VerificationRelationShipEntry{
			types.VerificationRelationShipEntry{
				Reference: &vmID,
			},
		},
	}

	return doc, nil
}

func Resolve(did string) (*types.DidDocument, error) {
	Initialize()

	if did == "" {
		return nil, errors.New("DID cannot be empty")
	}

	var doc []byte
	var err error
	//TODO did key
	if strings.HasPrefix(did, "did:jwk") {
		return resolveDidJwk(did)
	} else {
		doc, err = resolveWithResolver(did)
	}

	d, err := ParseDidDocument(string(doc))

	if err != nil {
		return nil, err
	}

	return d, nil
}
