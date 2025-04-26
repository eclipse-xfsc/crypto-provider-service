// nolint:revive
//lint:file-ignore ST1001 Ignore this lint rule for this file

package design

import (
	"time"
	// nolint:staticcheck
	. "goa.design/goa/v3/dsl"
)

type CredentialDataCredentialProofRequest struct {
	Context           []string  `json:"@context"`
	Type              []string  `json:"type"`
	Issuer            string    `json:"issuer"`
	IssuanceDate      time.Time `json:"issuanceDate"`
	CredentialSubject struct {
		Name  string `json:"name"`
		Allow bool   `json:"allow"`
	} `json:"credentialSubject"`
}

var CredentialProofRequest = Type("CredentialProofRequest", func() {
	Field(1, "namespace", String, "Key namespace.", func() {
		Example("transit")
	})
	Field(2, "key", String, "Key to use for the proof signature (optional).", func() {
		Example("key1")
	})
	Field(3, "credential", Any, "Verifiable Credential in JSON format or as sdjwt.", func() {
		credentialDataCredentialProofRequest := &CredentialDataCredentialProofRequest{
			Context:      []string{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1", "https://schema.org"},
			Type:         []string{"VerifiableCredential"},
			Issuer:       "did:web:nginx:policy:policy:example:example:1.0:evaluation",
			IssuanceDate: time.Date(2010, 01, 01, 19, 23, 24, 651387237, time.UTC),
			CredentialSubject: struct {
				Name  string "json:\"name\""
				Allow bool   "json:\"allow\""
			}{Name: "Alice", Allow: true},
		}
		Example(credentialDataCredentialProofRequest)
	})
	Field(4, "group", String, "Group identifies a group of keys within a namespace.", func() {
		Example("Group")
		Default("")
	})
	Field(5, "format", String, "identifies the format of the credential.", func() {
		Example("ldp_vc or vc+sd-jwt")
		Default("ldp_vc")
		Enum("ldp_vc", "vc+sd-jwt")
	})
	Field(6, "nonce", String, "Proof challenge", func() {
		Example("3483492392vvv-fff")
	})
	Field(7, "signatureType", String, "Type of signature.For sd-jwt is it automatically selected.", func() {
		Example("ed25519signature2020")
		Enum("ed25519signature2020", "jsonwebsignature2020")
		Default("jsonwebsignature2020")
	})
	Field(8, "disclosureFrame", ArrayOf(String), "Disclosed Attributes", func() {
		Example([]string{"email"})
	})
	Required("namespace", "key", "credential", "group")
})

var PresentationProofRequest = Type("PresentationProofRequest", func() {
	Field(1, "issuer", String, "Issuer DID used to specify proof verification info.")
	Field(2, "namespace", String, "Key namespace.", func() {
		Example("transit")
	})
	Field(3, "key", String, "Key to use for the proof signature.", func() {
		Example("key1")
	})
	Field(4, "presentation", Any, "Verifiable Presentation in JSON format.")
	Field(5, "group", String, "Group identifies a group of keys within a namespace.", func() {
		Example("Group")
		Default("")
	})
	Field(6, "nonce", String, "Proof challenge", func() {
		Example("3483492392vvv-fff")
	})
	Field(7, "signatureType", String, "Type of signature.For sd-jwt is it automatically selected.", func() {
		Example("ed25519signature2020")
		Enum("ed25519signature2020", "jsonwebsignature2020", "sdjwt")
		Default("jsonwebsignature2020")
	})
	Field(8, "format", String, "identifies the format of the credential.", func() {
		Example("ldp_vc or vc+sd-jwt")
		Default("ldp_vc")
		Enum("ldp_vc", "vc+sd-jwt")
	})
	Field(9, "disclosureFrame", ArrayOf(String), "Disclosed Attributes", func() {
		Example([]string{"email"})
	})
	Field(10, "aud", String, "audience", func() {
		Example("http://...")
	})
	Required("namespace", "key", "presentation", "group")
})

var CreatePresentationRequest = Type("CreatePresentationRequest", func() {
	Field(1, "issuer", String, "Issuer DID of the Verifiable Presentation.", func() {
		Example("did:web:example.com")
	})
	Field(2, "namespace", String, "Key namespace.", func() {
		Example("transit")
	})
	Field(3, "key", String, "Key to use for the proof signature.", func() {
		Example("key1")
	})
	Field(4, "data", ArrayOf(Any), "Raw JSON to be included inside the VP as Verifiable Credential.", func() {
		Example([]map[string]interface{}{
			{"hello": "world"},
			{"hola": "mundo"},
		})
	})
	Field(5, "context", ArrayOf(String), "Additional JSONLD contexts to be specified in the VP.", func() {
		Example([]string{
			"https://w3id.org/security/suites/jws-2020/v1",
			"https://schema.org",
		})
	})
	Field(6, "group", String, "Group identifies a group of keys within a namespace.", func() {
		Example("Group")
		Default("")
	})
	Field(7, "nonce", String, "Proof challenge", func() {
		Example("3483492392vvv-fff")
	})
	Field(8, "signatureType", String, "Type of signature. For sd-jwt is it automatically selected.", func() {
		Example("ed25519signature2020")
		Enum("ed25519signature2020", "jsonwebsignature2020")
		Default("jsonwebsignature2020")
	})
	Required("namespace", "key", "data", "group")
})

var CreateCredentialRequest = Type("CreateCredentialRequest", func() {
	Field(1, "issuer", String, "Issuer DID of the Verifiable Credential.", func() {
		Example("did:web:example.com")
	})
	Field(2, "namespace", String, "Key namespace.", func() {
		Example("transit")
	})
	Field(3, "key", String, "Key to use for the proof signature.", func() {
		Example("key1")
	})
	Field(4, "credentialSubject", Any, "Raw JSON that will be the VC subject.", func() {
		Example(map[string]interface{}{"hello": "world"})
	})
	Field(5, "context", ArrayOf(String), "Additional JSONLD contexts to be specified in the VC.", func() {
		Example([]string{
			"https://w3id.org/security/suites/jws-2020/v1",
			"https://schema.org",
		})
	})
	Field(6, "group", String, "Group identifies a group of keys within a namespace.", func() {
		Example("Group")
		Default("")
	})
	Field(7, "format", String, "identifies the format of the credential.", func() {
		Example("ldp_vc or vc+sd-jwt")
		Default("ldp_vc")
		Enum("ldp_vc", "vc+sd-jwt")
	})
	Field(8, "nonce", String, "Proof challenge", func() {
		Example("3483492392vvv-fff")
	})
	Field(9, "status", Boolean, "Append Status", func() {
		Example(true)
	})
	Field(10, "x-origin", String, "Origin of call", func() {
		Example("https://test")
	})
	Field(11, "signatureType", String, "Type of signature. For sd-jwt is it automatically selected.", func() {
		Example("ed25519signature2020")
		Enum("ed25519signature2020", "jsonwebsignature2020")
		Default("jsonwebsignature2020")
	})
	Field(12, "type", ArrayOf(String), "Type(s) of the credential. Just first one for sd-jwt used.", func() {
		Example([]string{"VerifiableCredential", "TestCredential]"})
	})
	Field(13, "disclosureFrame", ArrayOf(String), "Disclosed Attributes", func() {
		Example([]string{"email"})
	})
	Field(8, "holder", String, "Holder Binding", func() {
		Example("urn:3333:ddd")
	})
	Required("namespace", "key", "credentialSubject", "group", "x-origin")
})

var VerifyCredentialRequest = Type("VerifyCredentialRequest", func() {
	Field(1, "credential", Bytes, "Verifiable Credential in JSON format.")
	Field(2, "x-format", String, "format", func() {
		Example("ldp_vc or vc+sd-jwt")
		Default("ldp_vc")
		Enum("ldp_vc", "vc+sd-jwt")
	})
	Field(3, "x-namespace", String, "Namespace for status check")
	Field(4, "x-group", String, "Group for status check")
	Field(5, "disclosureFrame", ArrayOf(String), "Disclosed Attributes", func() {
		Example([]string{"email"})
	})
	Required("credential")
})

var VerifyPresentationRequest = Type("VerifyPresentationRequest", func() {
	Field(1, "presentation", Bytes, "Verifiable Presentation in JSON or sdjwt format.")
	Field(2, "disclosureFrame", ArrayOf(String), "Disclosed Attributes", func() {
		Example([]string{"email"})
	})
	Field(3, "x-format", String, "format", func() {
		Example("ldp_vc or vc+sd-jwt")
		Default("ldp_vc")
		Enum("ldp_vc", "vc+sd-jwt")
	})
	Field(3, "aud", String, "expected audience", func() {
	})
	Field(4, "nonce", String, "expected nonce", func() {
	})
	Required("presentation")
})

var VerifyResult = Type("VerifyResult", func() {
	Field(1, "valid", Boolean, "Valid specifies if the proof is successfully verified.")
	Field(2, "disclosedCredential", Any, "Disclosed Credential", func() {
	})
	Required("valid")
})

var NamespaceKeysRequest = Type("NamespaceKeysRequest", func() {
	Field(1, "namespace", String, "Namespace for signing keys.", func() {
		Example("did:web:example.com")
	})
	Field(2, "x-group", String, "Group identifies a group of keys within a namespace.", func() {
		Example("Group")
		Default("")
	})
	Required("namespace")
})

var VerificationMethodRequest = Type("VerificationMethodRequest", func() {
	Field(1, "namespace", String, "Key namespace.", func() {
		Example("transit")
	})
	Field(2, "key", String, "Name of requested key.", func() {
		Example("key1")
	})
	Field(3, "did", String, "DID controller of the key.", func() {
		Example("did:web:example.com")
	})
	Field(4, "group", String, "Group identifies a group of keys within a namespace.", func() {
		Example("Group")
		Default("")
	})
	Field(4, "engine", String, "Engine which shall be used. Eg transit or transit;kv or kv", func() {
		Example("transit")
		Default("transit")
	})
	Required("namespace", "key", "did")
})

var VerificationMethodsRequest = Type("VerificationMethodsRequest", func() {
	Field(1, "namespace", String, "Keys namespace.", func() {
		Example("transit")
	})
	Field(2, "did", String, "DID controller of the keys.", func() {
		Example("did:web:example.com")
	})
	Field(3, "group", String, "Group identifies a group of keys within a namespace.", func() {
		Example("Group")
		Default("")
	})
	Field(4, "engine", String, "Engine which shall be used. Eg transit or transit;kv or kv", func() {
		Example("transit")
		Default("transit")
	})
	Required("namespace", "did")
})

var DIDVerificationMethod = Type("DIDVerificationMethod", func() {
	Field(1, "id", String, "ID of verification method.", func() {
		Example("key1")
	})
	Field(2, "type", String, "Type of verification method key.", func() {
		Example("JsonWebKey2020")
	})
	Field(3, "controller", String, "Controller of verification method specified as DID.", func() {
		Example("did:web:example.com")
	})
	Field(4, "publicKeyJwk", Any, "Public Key encoded in JWK format.", func() {
		Example("https://openid.net/specs/draft-jones-json-web-key-03.html#ExampleJWK")
	})
	Required("id", "type", "controller", "publicKeyJwk")
})

var JwkPublicKeyRequest = Type("JwkPublicKeyRequest", func() {
	Field(1, "namespace", String, "Key namespace.", func() {
		Example("transit")
	})
	Field(2, "key", String, "Key name.", func() {
		Example("my-ecdsa-key1")
	})
	Field(3, "group", String, "Group identifies a group of keys within a namespace.", func() {
		Example("Group")
		Default("")
	})
	Field(4, "engine", String, "Engine which shall be used. Eg transit or transit;kv or kv", func() {
		Example("transit")
		Default("transit")
	})
	Required("namespace", "key", "group")
})

var SignRequest = Type("SignRequest", func() {
	Field(1, "namespace", String, "Key namespace to be used for signing.")
	Field(2, "key", String, "Key to be used for signing.")
	Field(3, "data", String, "Data that must be signed, encoded as base64 string.")
	Field(4, "group", String, "Group identifies a group of keys within a namespace.", func() {
		Example("Group")
		Default("")
	})
	Required("namespace", "key", "data", "group")
})

var SignResult = Type("SignResult", func() {
	Field(1, "signature", String, "Signature encoded as base64 string.")
	Required("signature")
})

var HealthResponse = Type("HealthResponse", func() {
	Field(1, "service", String, "Service name.")
	Field(2, "status", String, "Status message.")
	Field(3, "version", String, "Service runtime version.")
	Required("service", "status", "version")
})

var didRequest = Type("DidRequest", func() {
	Field(1, "x-namespace", String, "Namespace.", func() {
		Default("transit")
	})
	Field(2, "x-group", String, "Group.", func() {
		Example("Group")
		Default("")
	})
	Field(3, "x-did", String, "did which is used for controller and id", func() {
		Example("exampl:com")
		Default("did:web:localhost%3A:8080")
	})
	Field(4, "x-engine", String, "Engine which shall be used. Eg transit or transit;kv or kv", func() {
		Example("transit")
		Default("transit")
	})
})

var jwksRequest = Type("JwksRequest", func() {
	Field(1, "x-namespace", String, "Namespace.")
	Field(2, "x-group", String, "Group.", func() {})
	Field(3, "x-engine", String, "Engine which shall be used. Eg transit or transit;kv or kv", func() {
		Example("transit")
		Default("transit")
	})
	Required("x-namespace")
})

var jwksResponse = Type("JwksResponse", func() {
	Field(1, "keys", ArrayOf(Any), "List of jwk")
	Required("keys")
})

var didResponse = Type("DidResponse", func() {
	Field(1, "id", String, "did of the document")
	Field(2, "controller", String, "controler of the document")
	Field(3, "verificationMethod", ArrayOf(DIDVerificationMethod), "methods of the document")
	Field(4, "service", ArrayOf(serviceEndpoint), "serviceendpoints")
	Required("id", "controller")
})

var didListRequest = Type("DidListRequest", func() {
	Field(1, "x-namespace", String, "Namespace.")
	Field(2, "x-group", String, "Group.", func() {
		Example("Group")
		Default("")
	})
	Field(3, "x-engine", String, "Engine which shall be used. Eg transit or transit;kv or kv", func() {
		Example("transit")
		Default("transit")
	})
	Required("x-namespace")
})

var didListResponse = Type("DidListResponse", func() {
	Field(1, "list", ArrayOf(didListResponseItem), "did jwk list of keys")
	Required("list")
})

var didListResponseItem = Type("DidListResponseItem", func() {
	Field(1, "name", String, "name of the key.")
	Field(2, "did", String, "DID JWK of key")
	Required("name", "did")
})

var serviceEndpoint = Type("serviceEndpoint", func() {
	Field(1, "id", String, "did of the document")
	Field(2, "type", String, "type of endpoint")
	Field(3, "serviceEndpoint", String, "Endpoint URL")
	Required("id", "type", "serviceEndpoint")
})

var didConfigurationRequest = Type("DidConfiguration", func() {
	Field(1, "x-namespace", String, "Namespace.")
	Field(2, "x-group", String, "Group.", func() {
		Example("Group")
		Default("")
	})
	Field(3, "x-did", String, "did for the Configuration")
	Field(4, "x-origin", String, "origin for the configuration.")
	Field(5, "x-nonce", String, "Proof challenge", func() {
		Example("3483492392vvv-fff")
	})
	Field(6, "x-signatureType", String, "Type of signature", func() {
		Example("ed25519signature2020")
		Enum("ed25519signature2020", "jsonwebsignature2020")
		Default("jsonwebsignature2020")
	})
	Required("x-namespace", "x-origin")
})
