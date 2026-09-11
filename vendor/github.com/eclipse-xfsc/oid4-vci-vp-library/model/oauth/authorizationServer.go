package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/helper"
)

type GrantType string

const (
	PreAuthorizedCodeGrant GrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
	AuthorizationCodeGrant GrantType = "authorization_code"
)

const (
	AuthorizationDetailsTypeOpenIDCredential = "openid_credential"
)

type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`

	ExpiresIn int64 `json:"expires_in,omitempty"`

	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`

	AuthorizationDetails []AuthorizationDetails `json:"authorization_details,omitempty"`
}

type Claim struct {
	// Claims Path Pointer:
	// ["name"]
	// ["address", "street_address"]
	// ["degrees", nil, "type"]
	// ["nationalities", 1]
	Path []any `json:"path"`

	Mandatory bool `json:"mandatory,omitempty"`
}

type AuthorizationDetails struct {
	Type string `json:"type"`

	Locations []string `json:"locations,omitempty"`

	CredentialConfigurationID string `json:"credential_configuration_id,omitempty"`

	// This field is returned in the Token Response.
	CredentialIdentifiers []string `json:"credential_identifiers,omitempty"`

	Claims []Claim `json:"claims,omitempty"`
}

type OpenIdConfiguration struct {
	Issuer string `json:"issuer"`

	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string `json:"token_endpoint"`

	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`

	JwksUri string `json:"jwks_uri,omitempty"`

	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported    []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported  []string `json:"subject_types_supported,omitempty"`

	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`

	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported,omitempty"`

	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	ClaimsParameterSupported     bool `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported    bool `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported,omitempty"`
}

type TokenRequestOptions struct {
	PreAuthorizedCode string

	TxCode string

	AuthorizationDetails []AuthorizationDetails
}

func (config *OpenIdConfiguration) GetToken(
	grantType GrantType,
	options TokenRequestOptions,
) (*Token, error) {

	if config == nil {
		return nil, errors.New("openid configuration is nil")
	}

	if config.TokenEndpoint == "" {
		return nil, errors.New("token endpoint is missing")
	}

	switch grantType {

	case PreAuthorizedCodeGrant:
		return config.getPreAuthorizedCodeToken(options)

	default:
		return nil, fmt.Errorf(
			"unsupported grant type: %s",
			grantType,
		)
	}
}

func (config *OpenIdConfiguration) getPreAuthorizedCodeToken(
	options TokenRequestOptions,
) (*Token, error) {

	if options.PreAuthorizedCode == "" {
		return nil, errors.New(
			"pre-authorized code is required",
		)
	}

	formData := url.Values{
		"grant_type": {
			string(PreAuthorizedCodeGrant),
		},
		"pre-authorized_code": {
			options.PreAuthorizedCode,
		},
	}

	if options.TxCode != "" {
		formData.Set(
			"tx_code",
			options.TxCode,
		)
	}

	if len(options.AuthorizationDetails) > 0 {
		authorizationDetails, err := json.Marshal(
			options.AuthorizationDetails,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"could not marshal authorization_details: %w",
				err,
			)
		}

		formData.Set(
			"authorization_details",
			string(authorizationDetails),
		)
	}

	reader := strings.NewReader(
		formData.Encode(),
	)

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	body, err = helper.Post(
		config.TokenEndpoint,
		body,
		helper.ApplicationUrlForm,
		nil,
	)
	if err != nil {
		return nil, err
	}

	var token Token

	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf(
			"could not unmarshal token response: %w",
			err,
		)
	}

	if token.AccessToken == "" {
		return nil, errors.New(
			"token response contains no access_token",
		)
	}

	if token.TokenType == "" {
		return nil, errors.New(
			"token response contains no token_type",
		)
	}

	return &token, nil
}
