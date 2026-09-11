package credential

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/config"
	jwtext "github.com/eclipse-xfsc/ssi-jwt/v2"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	ProofTypeJWT         ProofVariant = "jwt"
	ProofTypeDIVP        ProofVariant = "di_vp"
	ProofTypeAttestation ProofVariant = "attestation"
)

const (
	DefaultNonceTTL       = 5 * time.Minute
	MinimumNonceSecretLen = 32
)

type CredentialResponseEncryptionParameters struct {
	JWK json.RawMessage `json:"jwk"`
	Enc string          `json:"enc"`
	Zip string          `json:"zip,omitempty"`
}

func (p *CredentialResponseEncryptionParameters) Validate() error {
	if p == nil {
		return nil
	}

	if len(p.JWK) == 0 {
		return errors.New("credential response encryption jwk is required")
	}

	if p.Enc == "" {
		return errors.New("credential response encryption enc is required")
	}

	return nil
}

type CredentialRequest struct {
	// Exactly one of CredentialIdentifier or CredentialConfigurationID
	// MUST be present.
	CredentialIdentifier string `json:"credential_identifier,omitempty"`

	CredentialConfigurationID string `json:"credential_configuration_id,omitempty"`

	// Proofs is optional unless proof_types_supported is advertised
	// for the selected Credential Configuration.
	Proofs *CredentialProofs `json:"proofs,omitempty"`

	CredentialResponseEncryption *CredentialResponseEncryptionParameters `json:"credential_response_encryption,omitempty"`

	// Format is accepted for interoperability with wallet implementations
	// using an older OID4VCI Credential Request structure.
	// It MUST NOT be used for credential selection in the 1.0 flow.
	Format string `json:"format,omitempty"`
	// Proof is accepted for interoperability with wallet implementations
	// using the legacy singular proof structure.
	// It should be normalized into Proofs before further processing.
	Proof *CredentialProof `json:"proof,omitempty"`
	// Legacy / wallet interoperability (WaltID)
	VCT string `json:"vct,omitempty"`
}

// CredentialProof represents the legacy singular proof structure used by

// older OID4VCI wallet implementations.

type CredentialProof struct {
	ProofType string `json:"proof_type,omitempty"`
	JWT       string `json:"jwt,omitempty"`
}

type CredentialProofs struct {
	JWT []string `json:"jwt,omitempty"`

	// A di_vp proof is a W3C Verifiable Presentation object.
	DIVP []json.RawMessage `json:"di_vp,omitempty"`

	// The attestation proof type MUST contain exactly one JWT.
	Attestation []string `json:"attestation,omitempty"`
}

type JWTKeyProofClaims struct {
	Issuer string `json:"iss,omitempty"`

	Audience string `json:"aud"`

	// NumericDate, not string.
	IssuedAt int64 `json:"iat"`

	// Required only when the Credential Issuer has a Nonce Endpoint.
	Nonce string `json:"nonce,omitempty"`
}

// NoncePayload is the payload protected by the HMAC.
//
// JTI provides randomness and prevents two generated nonces from being
// identical. Exp limits the lifetime of the nonce.
//
// Note: this does not provide one-time/replay protection by itself.
// For strict one-time semantics the JTI additionally needs to be consumed
// in a server-side store.
type NoncePayload struct {
	JTI      string `json:"jti"`
	TenantID string `json:"tenant_id"`
	Exp      int64  `json:"exp"`
}

func (r *CredentialRequest) Normalize() {
	if r == nil {
		return
	}

	// Prefer the OID4VCI 1.0 proofs structure if it is already present.
	if r.Proofs != nil {
		return
	}

	if r.Proof == nil {
		return
	}

	switch r.Proof.ProofType {
	case "jwt":
		if r.Proof.JWT != "" {
			r.Proofs = &CredentialProofs{
				JWT: []string{
					r.Proof.JWT,
				},
			}
		}
	}
}

// CreateNonce creates an opaque, HMAC-SHA256 protected nonce.
//
// Format:
//
//	base64url(payload).base64url(hmac)
//
// The returned value can be sent directly as c_nonce by the nonce endpoint.
func CreateNonce(
	secret string,
	tenantID string,
	ttl time.Duration,
) (string, error) {

	if len(secret) < MinimumNonceSecretLen {
		return "", fmt.Errorf(
			"nonce secret must contain at least %d characters",
			MinimumNonceSecretLen,
		)
	}

	if tenantID == "" {
		return "", errors.New("tenant id is required")
	}

	if ttl <= 0 {
		return "", errors.New("nonce TTL must be greater than zero")
	}

	jti, err := generateNonceJTI()
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce jti: %w", err)
	}

	payload := NoncePayload{
		JTI:      jti,
		TenantID: tenantID,
		Exp:      time.Now().Add(ttl).Unix(),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal nonce payload: %w", err)
	}

	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signature := signNonce(
		[]byte(secret),
		payloadEncoded,
	)

	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	return payloadEncoded + "." + signatureEncoded, nil
}

// ValidateNonce verifies the HMAC signature and expiration of an opaque nonce.
func ValidateNonce(
	secret string,
	tenantID string,
	nonce string,
) error {

	if secret == "" {
		return errors.New("nonce secret is missing")
	}

	if len(secret) < MinimumNonceSecretLen {
		return fmt.Errorf(
			"nonce secret must contain at least %d characters",
			MinimumNonceSecretLen,
		)
	}

	if tenantID == "" {
		return errors.New("tenant id is required")
	}

	if nonce == "" {
		return errors.New("nonce is missing")
	}

	parts := strings.Split(nonce, ".")
	if len(parts) != 2 {
		return errors.New("nonce has invalid format")
	}

	payloadEncoded := parts[0]
	signatureEncoded := parts[1]

	signature, err := base64.RawURLEncoding.DecodeString(signatureEncoded)
	if err != nil {
		return errors.New("nonce signature is invalid")
	}

	expectedSignature := signNonce(
		[]byte(secret),
		payloadEncoded,
	)

	if !hmac.Equal(signature, expectedSignature) {
		return errors.New("nonce signature is invalid")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return errors.New("nonce payload is invalid")
	}

	var payload NoncePayload

	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return errors.New("nonce payload is invalid")
	}

	if payload.JTI == "" {
		return errors.New("nonce jti is missing")
	}

	if payload.TenantID == "" {
		return errors.New("nonce tenant id is missing")
	}

	if payload.TenantID != tenantID {
		return errors.New("nonce tenant id does not match")
	}

	if payload.Exp == 0 {
		return errors.New("nonce expiration is missing")
	}

	if time.Now().Unix() >= payload.Exp {
		return errors.New("nonce has expired")
	}

	return nil
}

func signNonce(secret []byte, payload string) []byte {
	mac := hmac.New(sha256.New, secret)

	_, _ = mac.Write([]byte(payload))

	return mac.Sum(nil)
}

func generateNonceJTI() (string, error) {
	value := make([]byte, 32)

	if _, err := rand.Read(value); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (request *CredentialRequest) CheckRequestValid(
	audience string,
	tenantID string,
	nonceSecret string,
	proofTypesSupported map[ProofVariant]ProofType,
) (bool, error) {

	if request == nil {
		return false, errors.New("credential request is nil")
	}

	hasCredentialIdentifier := request.CredentialIdentifier != ""
	hasCredentialConfigurationID := request.CredentialConfigurationID != ""

	if hasCredentialIdentifier == hasCredentialConfigurationID {
		return false, errors.New(
			"exactly one of credential_identifier or credential_configuration_id must be present",
		)
	}

	if len(proofTypesSupported) > 0 {
		if request.Proofs == nil {
			return false, errors.New(
				"proofs are required for the requested credential configuration",
			)
		}

		if err := request.Proofs.CheckProofs(
			audience,
			tenantID,
			nonceSecret,
			proofTypesSupported,
		); err != nil {
			return false, err
		}
	}

	if request.CredentialResponseEncryption != nil {
		if err := request.CredentialResponseEncryption.Validate(); err != nil {
			return false, err
		}
	}

	return true, nil
}

func (proofs *CredentialProofs) CheckProofs(
	audience string,
	tenantID string,
	nonceSecret string,
	proofTypesSupported map[ProofVariant]ProofType,
) error {

	if proofs == nil {
		return errors.New("proofs are missing")
	}

	proofTypeCount := 0

	if len(proofs.JWT) > 0 {
		proofTypeCount++
	}

	if len(proofs.DIVP) > 0 {
		proofTypeCount++
	}

	if len(proofs.Attestation) > 0 {
		proofTypeCount++
	}

	if proofTypeCount == 0 {
		return errors.New("proofs must contain at least one proof")
	}

	if proofTypeCount != 1 {
		return errors.New("proofs must contain exactly one proof type")
	}

	switch {
	case len(proofs.JWT) > 0:
		if _, ok := proofTypesSupported[ProofTypeJWT]; !ok {
			return errors.New("jwt proof type is not supported")
		}

		for _, proof := range proofs.JWT {
			if err := checkJWTProof(
				proof,
				audience,
				tenantID,
				nonceSecret,
			); err != nil {
				return err
			}
		}

		return nil

	case len(proofs.DIVP) > 0:
		if _, ok := proofTypesSupported[ProofTypeDIVP]; !ok {
			return errors.New("di_vp proof type is not supported")
		}

		return errors.New("di_vp proof validation is not implemented")

	case len(proofs.Attestation) > 0:
		if _, ok := proofTypesSupported[ProofTypeAttestation]; !ok {
			return errors.New("attestation proof type is not supported")
		}

		if len(proofs.Attestation) != 1 {
			return errors.New(
				"attestation proof type must contain exactly one attestation",
			)
		}

		return errors.New("attestation proof validation is not implemented")
	}

	return errors.New("unsupported proof type")
}

func checkJWTProof(
	proof string,
	audience string,
	tenantID string,
	nonceSecret string,
) error {

	if proof == "" {
		return errors.New("jwt proof must not be empty")
	}

	options := []jwt.ParseOption{
		jwt.WithAcceptableSkew(config.DefaultLeeway),
		jwt.WithRequiredClaim("iat"),
	}

	if audience != "" {
		options = append(
			options,
			jwt.WithRequiredClaim("aud"),
			jwt.WithAudience(audience),
		)
	}

	if nonceSecret != "" {
		options = append(
			options,
			jwt.WithRequiredClaim("nonce"),
		)
	}

	jToken, err := jwtext.Parse(proof, options...)
	if err != nil {
		return fmt.Errorf(
			"failed to verify JWT proof: %w",
			err,
		)
	}

	if jToken == nil {
		return errors.New("JWT proof is invalid")
	}

	if err := checkJWTProofClaims(
		jToken,
		audience,
		tenantID,
		nonceSecret,
	); err != nil {
		return err
	}

	return nil
}

func checkJWTProofClaims(
	token jwt.Token,
	audience string,
	tenantID string,
	nonceSecret string,
) error {

	issuedAt := token.IssuedAt()

	if issuedAt.IsZero() {
		return errors.New("JWT proof is missing iat")
	}

	if audience != "" {
		aud := token.Audience()

		if len(aud) == 0 {
			return errors.New("JWT proof is missing aud")
		}

		found := false

		for _, value := range aud {
			if value == audience {
				found = true
				break
			}
		}

		if !found {
			return errors.New("JWT proof audience does not match")
		}
	}

	if nonceSecret != "" {
		nonceValue, ok := token.Get("nonce")
		if !ok {
			return errors.New("JWT proof is missing nonce")
		}

		nonce, ok := nonceValue.(string)
		if !ok {
			return errors.New("JWT proof nonce must be a string")
		}

		if err := ValidateNonce(
			nonceSecret,
			tenantID,
			nonce,
		); err != nil {
			return fmt.Errorf(
				"JWT proof nonce is invalid: %w",
				err,
			)
		}
	}

	return nil
}
