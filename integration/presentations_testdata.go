//lint:file-ignore U1000 Ignore this lint rule for this file

package integration

var presentationWithSubjectID = `
{
    "@context":
    [
		"https://www.w3.org/2018/credentials/v1",
		"https://w3id.org/security/suites/jws-2020/v1",
		"https://schema.org"
    ],
    "id": "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
    "type": "VerifiablePresentation",
    "verifiableCredential":
    [
        {
            "@context":
            [
				"https://www.w3.org/2018/credentials/v1",
				"https://schema.org"
            ],
            "id": "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
            "type": "VerifiableCredential",
            "issuer": "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
            "issuanceDate": "2010-01-01T19:23:24Z",
            "credentialSubject":
            {
				"id":"did:web:example.com",
                "allow": true
            }
        }
    ]
}`

var presentationWithoutSubjectID = `
{
    "@context":
    [
		"https://www.w3.org/2018/credentials/v1",
		"https://w3id.org/security/suites/jws-2020/v1",
		"https://schema.org"
    ],
    "id": "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
    "type": "VerifiablePresentation",
    "verifiableCredential":
    [
        {
            "@context":
            [
				"https://www.w3.org/2018/credentials/v1",
				"https://schema.org"
            ],
            "id": "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
            "type": "VerifiableCredential",
            "issuer": "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
            "issuanceDate": "2010-01-01T19:23:24Z",
            "credentialSubject":
            {
                "allow": true
            }
        }
    ]
}`

var presentationWithInvalidSubjectID = `
{
    "@context":
    [
		"https://www.w3.org/2018/credentials/v1",
		"https://w3id.org/security/suites/jws-2020/v1",
		"https://schema.org"
    ],
    "id": "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
    "type": "VerifiablePresentation",
    "verifiableCredential":
    [
        {
            "@context":
            [
				"https://www.w3.org/2018/credentials/v1",
				"https://schema.org"
            ],
            "id": "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
            "type": "VerifiableCredential",
            "issuer": "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
            "issuanceDate": "2010-01-01T19:23:24Z",
            "credentialSubject":
            {
				"id":"invalid",
                "allow": true
            }
        }
    ]
}`

var presentationWithNumericalSubjectID = `
{
    "@context":
    [
		"https://www.w3.org/2018/credentials/v1",
		"https://w3id.org/security/suites/jws-2020/v1",
		"https://schema.org"
    ],
    "id": "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
    "type": "VerifiablePresentation",
    "verifiableCredential":
    [
        {
            "@context":
            [
				"https://www.w3.org/2018/credentials/v1",
				"https://schema.org"
            ],
            "id": "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
            "type": "VerifiableCredential",
            "issuer": "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
            "issuanceDate": "2010-01-01T19:23:24Z",
            "credentialSubject":
            {
				"id":123,
                "allow": true
            }
        }
    ]
}`

var presentationWithMissingCredentialContext = `
{
    "@context":
    [
		"https://www.w3.org/2018/credentials/v1",
		"https://w3id.org/security/suites/jws-2020/v1",
		"https://schema.org"
    ],
    "id": "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
    "type": "VerifiablePresentation",
    "verifiableCredential":
    [
        {
            "@context":
            [
				"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"
            ],
            "credentialSubject":
            {
                "age_over": 18,
                "allow": false,
                "citizenship": "France",
                "id": "https://ssi-dev.vereign.com/tsa/policy/policy/example/example/1.0/evaluation"
            },
            "issuanceDate": "2022-07-21T10:24:36.203848291Z",
            "issuer": "did:web:yourdomain.com:policy:policies:example:returnDID:1.0:evaluation",
            "type": "VerifiableCredential"
        }
    ]
}`
