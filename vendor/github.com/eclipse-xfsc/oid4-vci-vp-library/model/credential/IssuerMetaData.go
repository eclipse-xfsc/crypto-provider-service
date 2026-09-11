package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/helper"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/oauth"
)

type IssuerMetadata struct {
	CredentialIssuer string `json:"credential_issuer"`

	AuthorizationServers []string `json:"authorization_servers,omitempty"`

	CredentialEndpoint         string  `json:"credential_endpoint"`
	NonceEndpoint              *string `json:"nonce_endpoint,omitempty"`
	DeferredCredentialEndpoint *string `json:"deferred_credential_endpoint,omitempty"`
	NotificationEndpoint       *string `json:"notification_endpoint,omitempty"`

	CredentialRequestEncryption  *CredentialRequestEncryption  `json:"credential_request_encryption,omitempty"`
	CredentialResponseEncryption *CredentialResponseEncryption `json:"credential_response_encryption,omitempty"`

	BatchCredentialIssuance *BatchCredentialIssuance `json:"batch_credential_issuance,omitempty"`

	Display []LocalizedCredential `json:"display,omitempty"`

	SignedMetadata *string `json:"signed_metadata,omitempty"`

	CredentialConfigurationsSupported map[string]CredentialConfiguration `json:"credential_configurations_supported"`
}

// CredentialRequestEncryption describes the Credential Issuer's
// capabilities for encrypted Credential Requests.
//
// According to OID4VCI 1.0, the Issuer publishes one or more public
// encryption keys through jwks. The Wallet uses these keys for
// encrypting Credential Requests.
type CredentialRequestEncryption struct {
	JWKs               JWKSet   `json:"jwks"`
	EncValuesSupported []string `json:"enc_values_supported"`
	ZipValuesSupported []string `json:"zip_values_supported,omitempty"`
	EncryptionRequired bool     `json:"encryption_required"`
}

// CredentialResponseEncryption describes the Credential Issuer's
// capabilities for encrypted Credential Responses.
type CredentialResponseEncryption struct {
	AlgValuesSupported []string `json:"alg_values_supported"`
	EncValuesSupported []string `json:"enc_values_supported"`
	ZipValuesSupported []string `json:"zip_values_supported,omitempty"`
	EncryptionRequired bool     `json:"encryption_required"`
}

// JWKSet represents the public keys advertised by the Credential Issuer
// for encrypted Credential Requests.
//
// json.RawMessage is intentionally used here to avoid coupling the protocol
// model to a specific JOSE implementation.
type JWKSet struct {
	Keys []json.RawMessage `json:"keys"`
}

// BatchCredentialIssuance indicates that the Credential Endpoint accepts
// more than one key proof in a Credential Request and therefore can issue
// multiple Credentials for the same Credential Dataset.
type BatchCredentialIssuance struct {
	BatchSize uint `json:"batch_size"`
}

type CredentialConfigurationIdentifier struct {
	Id                    string   `json:"configuration_id"`
	CredentialIdentifiers []string `json:"credential_identifiers,omitempty"`
}

type CredentialConfiguration struct {
	Format string `json:"format"`

	Scope string `json:"scope,omitempty"`

	CryptographicBindingMethodsSupported []string `json:"cryptographic_binding_methods_supported,omitempty"`

	CredentialSigningAlgValuesSupported []string `json:"credential_signing_alg_values_supported,omitempty"`

	CredentialDefinition *CredentialDefinition `json:"credential_definition,omitempty"`

	ProofTypesSupported map[ProofVariant]ProofType `json:"proof_types_supported,omitempty"`

	// Format-specific parameter for SD-JWT VC.
	Vct *string `json:"vct,omitempty"`

	// Format-specific metadata.
	Order  []string        `json:"order,omitempty"`
	Claims []MetadataClaim `json:"claims,omitempty"`

	CredentialMetadata *CredentialMetadata `json:"credential_metadata,omitempty"`

	// XFSC internal fields.
	//
	// These fields are not part of OID4VCI.
	// The well-known-service must strip these fields from metadata returned
	// to Wallets. They may remain in internal/NATS messages so that services
	// can route issuance requests.
	Schema  map[string]interface{} `json:"schema,omitempty"`
	Subject string                 `json:"topic,omitempty"`
}

type CredentialMetadata struct {
	Claims  []oauth.Claim         `json:"claims,omitempty"`
	Display []LocalizedCredential `json:"display,omitempty"`
}

type CredentialDefinition struct {
	Context []string `json:"@context,omitempty"`
	Type    []string `json:"type"`

	CredentialSubject map[string]CredentialSubject `json:"credentialSubject,omitempty"`
}

type MetadataClaim struct {
	oauth.Claim

	Display []Display `json:"display,omitempty"`
}

type CredentialSubject struct {
	Display []Display `json:"display,omitempty"`
}

type Display struct {
	Name   string `json:"name"`
	Locale string `json:"locale,omitempty"`
}

type ProofType struct {
	ProofSigningAlgValuesSupported []string `json:"proof_signing_alg_values_supported"`

	KeyAttestationsRequired *KeyAttestationsRequired `json:"key_attestations_required,omitempty"`
}

type KeyAttestationsRequired struct {
	KeyStorage         []string `json:"key_storage,omitempty"`
	UserAuthentication []string `json:"user_authentication,omitempty"`
}

type ProofVariant string

const (
	ProofJWT         ProofVariant = "jwt"
	ProofDIVP        ProofVariant = "di_vp"
	ProofAttestation ProofVariant = "attestation"
)

var ProofVariants = []ProofVariant{
	ProofJWT,
	ProofDIVP,
	ProofAttestation,
}

type LocalizedCredential struct {
	Name   string `json:"name,omitempty"`
	Locale string `json:"locale,omitempty"`

	Logo *DescriptiveURL `json:"logo,omitempty"`

	Description     string          `json:"description,omitempty"`
	BackgroundColor string          `json:"background_color,omitempty"`
	BackgroundImage *DescriptiveURL `json:"background_image,omitempty"`
	TextColor       string          `json:"text_color,omitempty"`
}

type DescriptiveURL struct {
	URI             string `json:"uri"`
	AlternativeText string `json:"alt_text,omitempty"`
}

func (metadata *IssuerMetadata) CredentialRequest(
	request CredentialRequest,
	token oauth.Token,
) (*CredentialResponse, error) {

	b, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	b, err = helper.Post(
		metadata.CredentialEndpoint,
		b,
		helper.ApplicationJson,
		&token.AccessToken,
	)
	if err != nil {
		return nil, err
	}

	var response CredentialResponse

	if err := json.Unmarshal(b, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

func (metadata *IssuerMetadata) FindFittingAuthorizationServer(
	grant oauth.GrantType,
) (*oauth.OpenIdConfiguration, error) {

	authorizationServers := metadata.AuthorizationServers

	// If authorization_servers is omitted, OID4VCI specifies that the
	// Credential Issuer itself acts as the Authorization Server.
	if len(authorizationServers) == 0 {
		authorizationServers = []string{
			metadata.CredentialIssuer,
		}
	}

	for _, server := range authorizationServers {
		config, err := findAuthorizationServerConfiguration(server)
		if err != nil {
			continue
		}

		if slices.Contains(config.GrantTypesSupported, string(grant)) {
			return config, nil
		}
	}

	return nil, fmt.Errorf(
		"no authorization server supporting grant type %q found",
		grant,
	)
}

func findAuthorizationServerConfiguration(
	issuer string,
) (*oauth.OpenIdConfiguration, error) {

	var lastErr error

	// OID4VCI 1.0 refers to RFC 8414 OAuth Authorization Server Metadata.
	//
	// Try that endpoint first.
	endpoints := []string{
		authorizationServerMetadataURL(issuer),

		// Keep OpenID Connect discovery as a compatibility fallback because
		// existing XFSC deployments currently expose this endpoint.
		openIDConfigurationURL(issuer),
	}

	for _, endpoint := range endpoints {
		b, err := helper.Get(endpoint)
		if err != nil {
			lastErr = err
			continue
		}

		var config oauth.OpenIdConfiguration

		if err := json.Unmarshal(b, &config); err != nil {
			lastErr = err
			continue
		}

		return &config, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, errors.New("unable to retrieve authorization server metadata")
}

// authorizationServerMetadataURL builds the RFC 8414 metadata URL.
//
// Example:
//
//	https://example.com
//	-> https://example.com/.well-known/oauth-authorization-server
//
//	https://example.com/tenant
//	-> https://example.com/.well-known/oauth-authorization-server/tenant
func authorizationServerMetadataURL(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return strings.TrimRight(issuer, "/") +
			"/.well-known/oauth-authorization-server"
	}

	issuerPath := strings.Trim(u.Path, "/")

	if issuerPath == "" {
		u.Path = "/.well-known/oauth-authorization-server"
	} else {
		u.Path = "/.well-known/oauth-authorization-server/" + issuerPath
	}

	u.RawQuery = ""
	u.Fragment = ""

	return u.String()
}

// openIDConfigurationURL is retained for compatibility with Authorization
// Servers exposing OpenID Connect Discovery rather than RFC 8414 metadata.
func openIDConfigurationURL(issuer string) string {
	return strings.TrimRight(issuer, "/") +
		"/.well-known/openid-configuration"
}
