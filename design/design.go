// nolint:revive
//lint:file-ignore ST1001 Ignore this lint rule for this file

package design

import . "goa.design/goa/v3/dsl"

var _ = API("signer", func() {
	Title("Signer Service")
	Description("Signer service exposes HTTP API for making and verifying digital signatures and proofs for Verifiable Credentials.")
	Server("signer", func() {
		Description("Signer Server")
		Host("development", func() {
			Description("Local development server")
			URI("http://localhost:8085")
		})
	})
})

var _ = Service("signer", func() {
	Description("Signer service makes digital signatures and proofs for verifiable credentials and presentations.")

	Method("Namespaces", func() {
		Description("Namespaces returns all keys namespaces, which corresponds to enabled Vault transit engines.")
		Payload(Empty)
		Result(ArrayOf(String), "List of available keys namespaces.")
		HTTP(func() {
			GET("/v1/namespaces")
			Response(StatusOK)
		})
	})

	Method("NamespaceKeys", func() {
		Description("NamespaceKeys returns all keys in a given namespace.")
		Payload(NamespaceKeysRequest)
		Result(ArrayOf(String), "Array of key names in a given namespace.")
		HTTP(func() {
			Header("x-group", String, func() {})
			GET("/v1/namespaces/{namespace}/keys")
			Response(StatusOK)
		})
	})

	Method("VerificationMethod", func() {
		Description("VerificationMethod returns a single public key formatted as DID verification method for a given namespace, key and did. When did:jwk is set for did, a did:jwk is generated from the key.")
		Payload(VerificationMethodRequest)
		Result(DIDVerificationMethod, "Public Key represented as DID Verification Method.")
		HTTP(func() {
			GET("/v1/verification-methods/{namespace}/{key}/{did}")
			Response(StatusOK)
		})
	})

	Method("VerificationMethods", func() {
		Description("VerificationMethods returns all public keys in a given namespace. The result is formatted as array of DID verification methods with their controller attribute being the given DID in the request.")
		Payload(VerificationMethodsRequest)
		Result(ArrayOf(DIDVerificationMethod), "Array of public keys represented as DID Verification Methods.")
		HTTP(func() {
			GET("/v1/verification-methods/{namespace}/{did}")
			Response(StatusOK)
		})
	})

	Method("JwkPublicKey", func() {
		Description("JwkPublicKey returns public key by name and namespace.")
		Payload(JwkPublicKeyRequest)
		Result(Any, "Public key encoded as JSON Web Key.")
		HTTP(func() {
			GET("/v1/jwk/{namespace}/{key}")
			Response(StatusOK)
			Response(StatusNotFound)
			Response(StatusInternalServerError)
		})
	})

	Method("CredentialProof", func() {
		Description("CredentialProof adds a proof to a given Verifiable Credential.")
		Payload(CredentialProofRequest)
		Result(Any)
		HTTP(func() {
			POST("/v1/credential/proof")
			Response(StatusOK)
		})
	})

	Method("PresentationProof", func() {
		Description("PresentationProof adds a proof to a given Verifiable Presentation.")
		Payload(PresentationProofRequest)
		Result(Any)
		HTTP(func() {
			POST("/v1/presentation/proof")
			Response(StatusOK)
		})
	})

	Method("CreateCredential", func() {
		Description("CreateCredential creates VC with proof from raw JSON data.")
		Payload(CreateCredentialRequest)
		Result(Any)
		HTTP(func() {
			Header("x-origin", String, func() {})
			POST("/v1/credential")
			Response(StatusOK)
		})
	})

	Method("CreatePresentation", func() {
		Description("CreatePresentation creates VP with proof from raw JSON data.")
		Payload(CreatePresentationRequest)
		Result(Any)
		HTTP(func() {
			POST("/v1/presentation")
			Response(StatusOK)
		})
	})

	Method("VerifyCredential", func() {
		Description("VerifyCredential verifies the proof of a Verifiable Credential.")
		Payload(VerifyCredentialRequest)
		Result(VerifyResult)

		HTTP(func() {
			Header("x-format", String, func() {
			})
			Header("x-namespace", String, func() {
			})
			Header("x-group", String, func() {
			})
			POST("/v1/credential/verify")
			Response(StatusOK)
		})
	})

	Method("VerifyPresentation", func() {
		Description("VerifyPresentation verifies the proof of a Verifiable Presentation.")
		Payload(VerifyPresentationRequest)
		Result(VerifyResult)
		HTTP(func() {
			Header("x-format", String, func() {
			})
			POST("/v1/presentation/verify")
			Response(StatusOK)
		})
	})

	Method("Sign", func() {
		Description("Sign creates digital signature on base64 encoded binary data.")
		Payload(SignRequest)
		Result(SignResult)
		HTTP(func() {
			POST("/v1/sign")
			Response(StatusOK)
			Response(StatusNotFound)
			Response(StatusInternalServerError)
		})
	})
	Method("didDoc", func() {
		Payload(didRequest)
		Result(didResponse)
		HTTP(func() {
			Header("x-namespace", String, func() {})
			Header("x-group", String, func() {})
			Header("x-did", String, func() {})
			Header("x-engine", String, func() {})
			GET("/v1/did/document")
			Response(StatusOK)
			Response(StatusNotFound)
			Response(StatusInternalServerError)
		})
	})
	Method("didList", func() {
		Payload(didListRequest)
		Result(didListResponse)
		HTTP(func() {
			Header("x-namespace", String, func() {})
			Header("x-group", String, func() {})
			Header("x-engine", String, func() {})
			GET("/v1/did/list")
			Response(StatusOK)
			Response(StatusNotFound)
			Response(StatusInternalServerError)
		})
	})

	Method("DidConfiguration", func() {
		Description("Creates did configuration.")
		Payload(didConfigurationRequest)
		Result(Any)
		HTTP(func() {
			Header("x-namespace", String, func() {})
			Header("x-group", String, func() {})
			Header("x-origin", String, func() {})
			Header("x-did", String, func() {})
			Header("x-nonce", String, func() {})
			GET("/v1/did/configuration")
			Response(StatusOK)
		})
	})

	Method("Jwks", func() {
		Payload(jwksRequest)
		Result(jwksResponse)
		HTTP(func() {
			Header("x-namespace", String, func() {})
			Header("x-group", String, func() {})
			Header("x-engine", String, func() {})
			GET("/v1/jwks")
			Response(StatusOK)
			Response(StatusNotFound)
			Response(StatusInternalServerError)
		})
	})
})

var _ = Service("health", func() {
	Description("Health service provides health check endpoints.")

	Method("Liveness", func() {
		Payload(Empty)
		Result(HealthResponse)
		HTTP(func() {
			GET("/liveness")
			Response(StatusOK)
		})
	})

	Method("Readiness", func() {
		Payload(Empty)
		Result(HealthResponse)
		HTTP(func() {
			GET("/readiness")
			Response(StatusOK)
		})
	})
})

var _ = Service("openapi", func() {
	Description("The openapi service serves the OpenAPI(v3) definition.")
	Meta("swagger:generate", "false")
	HTTP(func() {
		Path("/swagger-ui")
	})
	Files("/openapi.json", "./gen/http/openapi3.json", func() {
		Description("JSON document containing the OpenAPI(v3) service definition")
	})
	Files("/{*filepath}", "./swagger/")
})
