package credential

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/sirupsen/logrus"
	jwtext "gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/jwt"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/config"
)

const (
	ProofTypeJWT   = "jwt"
	ProofTypeCWT   = "cwt"
	ProofTypeLDPvP = "ldp_vp"
)

type CredentialRequest struct {
	Format               string                 `json:"format,omitempty"`
	CredentialIdentifier string                 `json:"credential_identifier,omitempty"`
	Proof                *Proof                 `json:"proof,omitempty"`
	Vct                  string                 `json:"vct,omitempty"`
	Claims               map[string]interface{} `json:"claims,omitempty"`
}

type Proof struct {
	ProofType string  `json:"proof_type"`
	Jwt       *string `json:"jwt"`
	Cwt       *string `json:"cwt"`
	LdpVp     *string `json:"ldp_vp"`
}

type JwtKeyProofType struct {
	Nonce    string `json:"nonce"`
	Issuer   string `json:"iss,omitempty"`
	Audience string `json:"aud"`
	IssuedAt string `json:"iat"`
}

func (proof *Proof) GetProof() *string {
	if proof.ProofType == ProofTypeJWT {
		return proof.Jwt
	}
	if proof.ProofType == ProofTypeCWT {
		return proof.Cwt
	}

	if proof.ProofType == ProofTypeLDPvP {
		return proof.LdpVp
	}
	return nil
}

func (proof *Proof) CheckProof(audience string, cNonce string) (*jwt.Token, error) {
	logrus.Debug(proof.Jwt)

	var jToken jwt.Token
	var err error
	options := []jwt.ParseOption{
		jwt.WithAcceptableSkew(config.DefaultLeeway),
		jwt.WithRequiredClaim("nonce"),
		jwt.WithClaimValue("nonce", cNonce),
	}

	if audience != "" {
		options = append(options, jwt.WithAudience(audience))
	}

	if proof.ProofType == "jwt" {
		jToken, err = jwtext.ParseSelfSigned(*proof.Jwt, options...)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("failed to verify signature of proof"), err)
		} else if jToken == nil {
			return nil, fmt.Errorf("failed to verify signature of proof, signature INVALID or expired! ")
		}
	} else {
		if proof.ProofType == "cwt" {

		} else {
			return nil, fmt.Errorf("Invalid proof type, expected %s, got %s", "cwt", proof.ProofType)
		}
	}

	return &jToken, nil
}

func (request *CredentialRequest) CheckRequestValid(audience string, cNonce string, validTypes []string) (*jwt.Token, error) {

	token, err := request.Proof.CheckProof(audience, cNonce)

	if err == nil {

		/*if reflect.DeepEqual(request.Types, validTypes) {
			return nil, fmt.Errorf("CredentialRequest: invalid type, expected %s, got %s", validTypes, request.Types)
		}*/

		expectedFormat := "vc+sd-jwt"
		if request.Format != expectedFormat {
			return nil, fmt.Errorf("CredentialRequest: invalid format, expected %s, got %s", expectedFormat, request.Format)
		}
	}
	return token, err
}
