package oauth

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/helper"
)

type GrantType string

const (
	PreAuthorizedCodeGrant GrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
	AuthorizationCodeGrant GrantType = "authorization_code"
)

type Token struct {
	AccessToken          string                `json:"access_token"`
	TokenType            string                `json:"token_type"`
	ExpiresIn            int64                 `json:"expires_in"`
	CNonce               string                `json:"c_nonce"`
	CNonceExpiresIn      int64                 `json:"c_nonce_expires_in"`
	AuthorizationDetails *AuthorizationDetails `json:"authorization_details,omitempty"`
}

type Claim struct {
	Path      string `json:"path"`
	Mandatory bool   `json:"mandatory"`
}

type AuthorizationDetails struct {
	Type                      string   `json:"type"`
	CredentialConfigurationID string   `json:"credential_configuration_id"`
	CredentialIdentifiers     []string `json:"credential_identifiers,omitempty"`
	Claims                    []Claim  `json:"claims,omitempty"`
}

type OpenIdConfiguration struct {
	Issuer                                           string   `json:"issuer"`
	Authorization_Endpoint                           string   `json:"authorization_endpoint"`
	Token_Endpoint                                   string   `json:"token_endpoint"`
	User_Endpoint                                    string   `json:"userinfo_endpoint"`
	Jwks_Uri                                         string   `json:"jwks_uri"`
	Scopes_Supported                                 []string `json:"scopes_supported"`
	Response_Types_Supported                         []string `json:"response_types_supported"`
	Grant_Types_Supported                            []string `json:"grant_types_supported"`
	Subject_Types_Supported                          []string `json:"subject_types_supported"`
	Id_Token_Signing_Alg_Values_Supported            []string `json:"id_token_signing_alg_values_supported"`
	Id_Token_Encryption_Alg_Values_Supported         []string `json:"id_token_encryption_alg_values_supported"`
	Id_Token_Encryption_Enc_Values_Supported         []string `json:"id_token_encryption_enc_values_supported"`
	Token_Endpoint_Auth_Methods_Supported            []string `json:"token_endpoint_auth_methods_supported"`
	Token_Endpoint_Auth_Signing_Alg_Values_Supported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	Claims_Parameter_Supported                       bool     `json:"claims_parameter_supported"`
	Request_Parameter_Supported                      bool     `json:"request_parameter_supported"`
	Request_Uri_Parameter_Supported                  bool     `json:"request_uri_parameter_supported"`
}

func (config *OpenIdConfiguration) GetToken(grantType GrantType, options map[string]interface{}) (*Token, error) {

	if grantType == PreAuthorizedCodeGrant {

		interval, ok := options["interval"].(int)

		if ok {
			if interval > 0 && interval < 10 { //be carefull with intervals from outside, can DDOS the system via link
				time.Sleep(time.Second * time.Duration(interval))
			} else {
				if interval > 10 {
					interval = 5
				}
			}
		}

		tx_code, ok := options["tx_code"].(string)

		formData := url.Values{
			"grant_type":          {string(grantType)},
			"pre-authorized_code": {options["code"].(string)},
		}

		if ok {
			formData.Add("tx_code", tx_code)
		}

		reader := strings.NewReader(formData.Encode())

		b, err := io.ReadAll(reader)

		if err != nil {
			return nil, err
		}

		b, err = helper.Post(config.Token_Endpoint, b, helper.ApplicationUrlForm, nil)

		if err != nil {
			return nil, err
		}

		var tokenReply Token

		err = json.Unmarshal(b, &tokenReply)

		if err != nil {
			return nil, err
		}

		return &tokenReply, nil
	}

	return nil, errors.New("token request failed")
}
