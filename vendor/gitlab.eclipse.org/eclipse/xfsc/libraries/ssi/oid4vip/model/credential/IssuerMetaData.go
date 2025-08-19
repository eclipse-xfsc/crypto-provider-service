package credential

import (
	"encoding/json"
	"errors"
	"strings"

	"golang.org/x/exp/slices"

	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/helper"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/oauth"
)

type IssuerMetadata struct {
	CredentialIssuer                  string                             `json:"credential_issuer"`
	AuthorizationServers              []string                           `json:"authorization_servers"`
	CredentialEndpoint                string                             `json:"credential_endpoint"`
	BatchCredentialEndpoint           *string                            `json:"batch_credential_endpoint"`
	DeferredCredentialEndpoint        *string                            `json:"deferred_credential_endpoint"`
	NotificationEndpoint              *string                            `json:"notification_endpoint"`
	CredentialResponseEncryption      CredentialRespEnc                  `json:"credential_response_encryption"`
	Display                           []LocalizedCredential              `json:"display"`
	CredentialIdentifiersSupported    bool                               `json:"credential_identifiers_supported"`
	SignedMetadata                    *string                            `json:"signed_metadata"`
	CredentialConfigurationsSupported map[string]CredentialConfiguration `json:"credential_configurations_supported"`
}

type CredentialRespEnc struct {
	AlgValuesSupported []string `json:"alg_values_supported"`
	EncValuesSupported []string `json:"enc_values_supported"`
	EncryptionRequired bool     `json:"encryption_required"`
}

type CredentialConfiguration struct {
	Format                               string                 `json:"format"`
	Scope                                string                 `json:"scope"`
	CryptographicBindingMethodsSupported []string               `json:"cryptographic_binding_methods_supported"`
	CredentialSigningAlgValuesSupported  []string               `json:"credential_signing_alg_values_supported"`
	CredentialDefinition                 CredentialDefinition   `json:"credential_definition"`
	ProofTypesSupported                  map[string]ProofType   `json:"proof_types_supported"`
	Display                              []LocalizedCredential  `json:"display"`
	Vct                                  *string                `json:"vct,omitempty"`
	Claims                               map[string]interface{} `json:"claims,omitempty"`
	Order                                []string               `json:"order,omitempty"`
	///Out of OID Spec, but useful
	Schema  map[string]interface{} `json:"schema,omitempty"` //json Schema representation of payload
	Subject string                 `json:"topic,omitempty"`  // Subject of the credential within the system
}

type CredentialDefinition struct {
	Type              []string                     `json:"type"`
	CredentialSubject map[string]CredentialSubject `json:"credentialSubject,omitempty"`
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
}

type LocalizedCredential struct {
	Name            string         `json:"name"`
	Locale          string         `json:"locale"`
	Logo            DescriptiveURL `json:"logo,omitempty"`
	BackgroundColor string         `json:"background_color,omitempty"`
	TextColor       string         `json:"text_color,omitempty"`
}

type DescriptiveURL struct {
	URL             string `json:"url"`
	AlternativeText string `json:"alternative_text"`
}

func (metadata *IssuerMetadata) CredentialRequest(request CredentialRequest, token oauth.Token) (*CredentialResponse, error) {

	b, err := json.Marshal(request)

	if err != nil {
		return nil, err
	}

	b, err = helper.Post(metadata.CredentialEndpoint, b, helper.ApplicationJson, &token.AccessToken)

	if err != nil {
		return nil, err
	}

	var response CredentialResponse
	err = json.Unmarshal(b, &response)

	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (metadata *IssuerMetadata) FindFittingAuthorizationServer(grant oauth.GrantType) (*oauth.OpenIdConfiguration, error) {

	if metadata.AuthorizationServers == nil || len(metadata.AuthorizationServers) == 0 {
		if metadata.AuthorizationServers != nil {
			metadata.AuthorizationServers = make([]string, 0)
		}
		metadata.AuthorizationServers = append(metadata.AuthorizationServers, metadata.CredentialIssuer)
	}

	for _, server := range metadata.AuthorizationServers {
		b, err := helper.Get(strings.Join([]string{server, ".well-known", "openid-configuration"}, "/"))

		if err == nil {
			var config oauth.OpenIdConfiguration
			err := json.Unmarshal(b, &config)
			if err == nil {
				contains := slices.Contains(config.Grant_Types_Supported, string(grant))
				if contains {
					return &config, nil
				}
			}
		}
	}

	return nil, errors.New("no fitting openidconfiguration found")
}
