package credential

import (
	"errors"
	"fmt"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/config"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/oauth"
	jwtext "github.com/eclipse-xfsc/ssi-jwt/v2"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/sirupsen/logrus"
)

const (
	ProofTypeJWT   = "jwt"
	ProofTypeCWT   = "cwt"
	ProofTypeLDPvP = "ldp_vp"
)

type CredentialRequest struct {
	///OID 1.0
	CredentialConfigurationId string `json:"credential_configuration_id,omitempty"`
	Proof                     *Proof `json:"proof,omitempty"`

	//Draft13, not more used in 1.0
	Format               string        `json:"format,omitempty"`
	CredentialIdentifier string        `json:"credential_identifier,omitempty"`
	Vct                  *string       `json:"vct,omitempty"`
	Claims               []oauth.Claim `json:"claims,omitempty"`
	Order                []string      `json:"order,omitempty"`
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

func (proof *Proof) CheckProof(audience string, cNonce string, proofTypesSupported map[ProofVariant]ProofType) error {

	logrus.Debug(proof)

	//no proofcheck required for this
	if len(proofTypesSupported) == 0 {
		return nil
	}

	_, ok := proofTypesSupported[ProofVariant(proof.ProofType)]

	if !ok {
		return errors.New("unsupported proof type")
	}

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
		jToken, err = jwtext.Parse(*proof.Jwt, options...)
		if err != nil {
			return errors.Join(fmt.Errorf("failed to verify signature of proof"), err)
		} else if jToken == nil {
			return errors.Join(fmt.Errorf("failed to verify signature of proof, signature INVALID or expired! "), err)
		}

		nonceInf, isSet := jToken.Get("nonce")
		if !isSet {
			return errors.Join(fmt.Errorf("invalid authorization specified (missing nonce)"), err)
		}

		if _, ok := nonceInf.(string); !ok {
			return errors.Join(fmt.Errorf("invalid nonce sepcified (expected string)"), err)
		}

		if nonceInf.(string) != cNonce {
			return errors.Join(fmt.Errorf("nonce is not matching"), err)
		}

		return nil

	} else {
		if proof.ProofType == "cwt" {

		} else {
			return errors.Join(fmt.Errorf("Invalid proof type, expected %s, got %s", "cwt", proof.ProofType), err)
		}
	}

	return nil
}

func (request *CredentialRequest) CheckRequestValid(audience string, cNonce string, proofTypesSupported map[ProofVariant]ProofType) (bool, error) {
	var err error
	b := false

	if request.Proof != nil && len(proofTypesSupported) > 0 {
		err := request.Proof.CheckProof(audience, cNonce, proofTypesSupported)
		if err != nil {
			return false, err
		}
	}

	if err == nil {
		if request.Format != "" && request.CredentialIdentifier != "" {
			return false, errors.New("either credential identifier or format is allowed")
		}

		if request.Format != "" {
			if request.Format == "vc+sd-jwt" {
				if request.Vct == nil {
					return false, errors.New("requested format has missing vct")
				}
			}
		}
	}

	return b, err
}
