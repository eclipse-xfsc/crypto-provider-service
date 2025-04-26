package jwkvdr

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	ariesjwk "github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

const (
	// DIDMethod did method.
	DIDMethod = "jwk"
	// EncryptionKey encryption key.
	EncryptionKey = "encryptionKey"
	// KeyType option to create a new kms key for DIDDocs with empty VerificationMethod.
	KeyType = "keyType"
)

// VDR implements did:key method support.
type VDR struct{}

// New returns new instance of VDR that works with did:key method.
func New() *VDR {
	return &VDR{}
}

// Accept accepts did:key method.
func (v *VDR) Accept(method string, opts ...vdrapi.DIDMethodOption) bool {
	return method == DIDMethod
}

// Close frees resources being maintained by VDR.
func (v *VDR) Close() error {
	return nil
}

// Update did doc.
func (v *VDR) Update(didDoc *diddoc.Doc, opts ...vdrapi.DIDMethodOption) error {
	return fmt.Errorf("not supported")
}

// Deactivate did doc.
func (v *VDR) Deactivate(didID string, opts ...vdrapi.DIDMethodOption) error {
	return fmt.Errorf("not supported")
}

func (v *VDR) Create(didDoc *did.Doc, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	return nil, fmt.Errorf("not supported")
}

func (v *VDR) Read(didKey string, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {

	encoded, _ := strings.CutPrefix(didKey, "did:jwk:")

	key, err := base64.RawURLEncoding.DecodeString(encoded)

	if err != nil {
		return nil, fmt.Errorf("encoding error %v", err.Error())
	}

	var jwk ariesjwk.JWK

	err = json.Unmarshal([]byte(key), &jwk)

	if err != nil {
		return nil, err
	}

	method, err := did.NewVerificationMethodFromJWK(didKey+"#0", "JsonWebKey2020", didKey, &jwk)

	if err != nil {
		return nil, fmt.Errorf("method error %v", err.Error())
	}
	didDoc := &did.Doc{
		ID:                 didKey,
		VerificationMethod: []did.VerificationMethod{*method},
	}

	return &did.DocResolution{DIDDocument: didDoc}, nil
}
