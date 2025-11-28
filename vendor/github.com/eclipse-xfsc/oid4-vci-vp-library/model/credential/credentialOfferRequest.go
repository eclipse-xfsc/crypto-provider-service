package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/helper"
)

type Grants struct {
	AuthorizationCode *AuthorizationCode `json:"authorization_code,omitempty"`
	PreAuthorizedCode *PreAuthorizedCode `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty"`
}

type TxCode struct {
	InputMode   string `json:"input_mode,omitempty"`
	Length      int    `json:"length,omitempty"`
	Description string `json:"description,omitempty"`
}

type PreAuthorizedCode struct {
	PreAuthorizationCode    string  `json:"pre-authorized_code"`
	TxCode                  *TxCode `json:"tx_code,omitempty"`
	Interval                int     `json:"interval,omitempty"`
	AuthorizationServerHint string  `json:"authorization_server,omitempty"`
}

type AuthorizationCode struct {
	IssuerState string `json:"issuer_state"`
}

type CredentialOfferParameters struct {
	CredentialIssuer string   `json:"credential_issuer"`
	Credentials      []string `json:"credential_configuration_ids"`
	Grants           Grants   `json:"grants"`
}

type CredentialOffer struct {
	CredentialOfferUri string `json:"credential_offer_uri,omitempty"`
	CredentialOffer    string `json:"credential_offer,omitempty"`
}

func (offerParameter *CredentialOfferParameters) CreateOfferLink() (*CredentialOffer, error) {
	marshal, err := json.Marshal(offerParameter)
	if err != nil {
		return nil, fmt.Errorf("could not marshal credentialOfferObject: %w", err)
	}

	credentialOfferJson := url.QueryEscape(string(marshal))

	return &CredentialOffer{
		CredentialOffer: fmt.Sprintf("openid-credential-offer://?credential_offer=%s", credentialOfferJson),
	}, nil
}

/*
Extracts the Parameters of the offering link
*/
func (offering *CredentialOffer) GetOfferParameters() (*CredentialOfferParameters, error) {
	var newCredentialOfferObject CredentialOfferParameters
	var rawObject []byte

	if offering.CredentialOffer != "" {
		slice := strings.Split(offering.CredentialOffer, "credential_offer=")
		unescaped, err := url.QueryUnescape(slice[len(slice)-1])
		if err != nil {
			return nil, err
		}
		rawObject = []byte(unescaped)

	} else if offering.CredentialOfferUri != "" {
		slice := strings.Split(offering.CredentialOfferUri, "credential_offer_uri=")
		unescape, err := url.QueryUnescape(slice[len(slice)-1])
		if err != nil {
			return nil, err
		}

		rawObject, err = helper.Get(unescape)
		if err != nil {
			return nil, err
		}

	} else {
		return nil, fmt.Errorf("no valid credentialOffer: %v", offering)
	}
	err := json.Unmarshal(rawObject, &newCredentialOfferObject)
	if err != nil {
		return nil, fmt.Errorf("error occured while unmarshal credentialOffer: %w", err)
	}

	return &newCredentialOfferObject, err
}

func (offerParameter *CredentialOfferParameters) GetIssuerMetadata() (*IssuerMetadata, error) {

	if offerParameter.CredentialIssuer != "" {

		b, err := helper.Get(strings.Join([]string{offerParameter.CredentialIssuer, ".well-known", "openid-credential-issuer"}, "/"))

		if err != nil {
			return nil, err
		}
		var metadata IssuerMetadata
		err = json.Unmarshal(b, &metadata)

		if err != nil {
			return nil, err
		}
		return &metadata, nil
	}
	return nil, errors.New("no issuer metadata found")
}
