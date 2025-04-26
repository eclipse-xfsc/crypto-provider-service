package types

import (
	"encoding/json"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/sirupsen/logrus"
)

type DidVerificationMethod struct {
	Id           string  `json:"id"`
	Controller   string  `json:"controller"`
	Type         string  `json:"type"`
	PublicKeyJwk jwk.Key `json:"publicKeyJwk,omitempty"`
}

type DidDocument struct {
	Id                 string                  `json:"id"`
	Controller         string                  `json:"controller"`
	VerificationMethod []DidVerificationMethod `json:"verificationMethod"`
}

func (d *DidDocument) GetPublicKeys() jwk.Set {
	METHOD_TYPE := "JsonWebKey2020"
	keys := jwk.NewSet()
	for _, item := range d.VerificationMethod {
		if item.Type == METHOD_TYPE {
			jwkJson, err := json.Marshal(item.PublicKeyJwk)
			if err == nil {
				key, err := jwk.ParseKey(jwkJson)
				key.Set(jwk.KeyIDKey, item.Id)
				if err == nil {
					keys.AddKey(key)
				} else {
					logrus.Info(item.Id + "is not valid JWK.")
				}
			} else {
				logrus.Info(item.Id + "is not valid JWK Definition.")
			}
		}
	}
	return keys
}
