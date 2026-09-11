package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/helper"
)

const (
	PreAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

type Grants struct {
	AuthorizationCode *AuthorizationCode `json:"authorization_code,omitempty"`

	PreAuthorizedCode *PreAuthorizedCode `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty"`
}

type TxCodeInputMode string

const (
	TxCodeInputModeNumeric TxCodeInputMode = "numeric"
	TxCodeInputModeText    TxCodeInputMode = "text"
)

type TxCode struct {
	InputMode   TxCodeInputMode `json:"input_mode,omitempty"`
	Length      int             `json:"length,omitempty"`
	Description string          `json:"description,omitempty"`
}

type PreAuthorizedCode struct {
	PreAuthorizedCode string `json:"pre-authorized_code"`

	TxCode *TxCode `json:"tx_code,omitempty"`

	AuthorizationServer string `json:"authorization_server,omitempty"`
}

type AuthorizationCode struct {
	IssuerState string `json:"issuer_state,omitempty"`

	AuthorizationServer string `json:"authorization_server,omitempty"`
}

type CredentialOfferParameters struct {
	CredentialIssuer string `json:"credential_issuer"`

	CredentialConfigurationIDs []string `json:"credential_configuration_ids"`

	Grants *Grants `json:"grants,omitempty"`
}

type CredentialOffer struct {
	CredentialOfferURI string `json:"credential_offer_uri,omitempty"`

	CredentialOffer string `json:"credential_offer,omitempty"`
}

func (offerParameters *CredentialOfferParameters) CreateOfferLink() (*CredentialOffer, error) {
	marshal, err := json.Marshal(offerParameters)
	if err != nil {
		return nil, fmt.Errorf("could not marshal credential offer object: %w", err)
	}

	credentialOfferJSON := url.QueryEscape(string(marshal))

	return &CredentialOffer{
		CredentialOffer: fmt.Sprintf(
			"openid-credential-offer://?credential_offer=%s",
			credentialOfferJSON,
		),
	}, nil
}

func (offer *CredentialOffer) GetOfferParameters() (*CredentialOfferParameters, error) {
	var offerParameters CredentialOfferParameters

	switch {
	case offer.CredentialOffer != "":
		rawObject, err := extractCredentialOffer(offer.CredentialOffer)
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(rawObject, &offerParameters); err != nil {
			return nil, fmt.Errorf(
				"could not unmarshal credential offer: %w",
				err,
			)
		}

	case offer.CredentialOfferURI != "":
		offerURI, err := extractCredentialOfferURI(offer.CredentialOfferURI)
		if err != nil {
			return nil, err
		}

		rawObject, err := helper.Get(offerURI)
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(rawObject, &offerParameters); err != nil {
			return nil, fmt.Errorf(
				"could not unmarshal credential offer: %w",
				err,
			)
		}

	default:
		return nil, errors.New("credential offer contains neither credential_offer nor credential_offer_uri")
	}

	if err := offerParameters.Validate(); err != nil {
		return nil, err
	}

	return &offerParameters, nil
}

func (offer *CredentialOfferParameters) Validate() error {
	if offer.CredentialIssuer == "" {
		return errors.New("credential_issuer is required")
	}

	if len(offer.CredentialConfigurationIDs) == 0 {
		return errors.New("credential_configuration_ids must not be empty")
	}

	seen := make(map[string]struct{}, len(offer.CredentialConfigurationIDs))

	for _, configurationID := range offer.CredentialConfigurationIDs {
		if configurationID == "" {
			return errors.New("credential_configuration_ids must not contain empty values")
		}

		if _, ok := seen[configurationID]; ok {
			return fmt.Errorf(
				"duplicate credential_configuration_id %q",
				configurationID,
			)
		}

		seen[configurationID] = struct{}{}
	}

	if offer.Grants != nil &&
		offer.Grants.PreAuthorizedCode != nil &&
		offer.Grants.PreAuthorizedCode.PreAuthorizedCode == "" {

		return errors.New("pre-authorized_code is required for pre-authorized code grant")
	}

	if offer.Grants != nil &&
		offer.Grants.PreAuthorizedCode != nil &&
		offer.Grants.PreAuthorizedCode.TxCode != nil {

		if err := offer.Grants.PreAuthorizedCode.TxCode.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (txCode TxCode) Validate() error {
	switch txCode.InputMode {
	case "", TxCodeInputModeNumeric, TxCodeInputModeText:
	default:
		return fmt.Errorf(
			"unsupported tx_code input_mode %q",
			txCode.InputMode,
		)
	}

	if txCode.Length < 0 {
		return errors.New("tx_code length must not be negative")
	}

	if len(txCode.Description) > 300 {
		return errors.New("tx_code description must not exceed 300 characters")
	}

	return nil
}

func (offer *CredentialOfferParameters) GetIssuerMetadata() (*IssuerMetadata, error) {
	if offer.CredentialIssuer == "" {
		return nil, errors.New("credential_issuer is required")
	}

	endpoint := strings.TrimRight(
		offer.CredentialIssuer,
		"/",
	) + "/.well-known/openid-credential-issuer"

	b, err := helper.Get(endpoint)
	if err != nil {
		return nil, err
	}

	var metadata IssuerMetadata

	if err := json.Unmarshal(b, &metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

func extractCredentialOffer(rawURI string) ([]byte, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, fmt.Errorf("invalid credential offer URI: %w", err)
	}

	credentialOffer := u.Query().Get("credential_offer")
	if credentialOffer == "" {
		return nil, errors.New("credential_offer parameter is missing")
	}

	if u.Query().Get("credential_offer_uri") != "" {
		return nil, errors.New(
			"credential_offer and credential_offer_uri must not both be present",
		)
	}

	return []byte(credentialOffer), nil
}

func extractCredentialOfferURI(rawURI string) (string, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return "", fmt.Errorf("invalid credential offer URI: %w", err)
	}

	credentialOfferURI := u.Query().Get("credential_offer_uri")
	if credentialOfferURI == "" {
		return "", errors.New("credential_offer_uri parameter is missing")
	}

	if u.Query().Get("credential_offer") != "" {
		return "", errors.New(
			"credential_offer and credential_offer_uri must not both be present",
		)
	}

	reference, err := url.Parse(credentialOfferURI)
	if err != nil {
		return "", fmt.Errorf("invalid credential_offer_uri: %w", err)
	}

	if reference.Scheme != "https" {
		return "", errors.New("credential_offer_uri must use https")
	}

	return credentialOfferURI, nil
}
