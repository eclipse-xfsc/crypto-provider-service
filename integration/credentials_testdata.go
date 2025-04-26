//lint:file-ignore U1000 Ignore this lint rule for this file

package integration

var credentialWithSubjectID = `
{
    "@context":
    [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
        "https://schema.org"
    ],
    "type": "VerifiableCredential",
    "issuer": "did:jwk:eyJjcnYiOiJQLTI1NiIsImtpZCI6ImVja2V5Iiwia3R5IjoiRUMiLCJ4IjoiNzhqejE4Wlh4NnZiQ2d4cHdhRGF4S1lkVUtHR185bVduQWNCNnA0YjVNWSIsInkiOiJQN1c2RFNGRV9aQTZBS1dfTEE5cE4zSFlPb1ZrUlJ1UjNublU1RzdRZmxNIn0",
    "issuanceDate": "2010-01-01T19:23:24Z",
    "credentialSubject":
    {
		"id":"did:web:example.com",
		"allow":true
    }
}`

var credentialWithoutSubjectID = `
{
    "@context":
    [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
        "https://schema.org"
    ],
    "type": "VerifiableCredential",
    "issuer": "did:jwk:eyJjcnYiOiJQLTI1NiIsImtpZCI6ImVja2V5Iiwia3R5IjoiRUMiLCJ4IjoiNzhqejE4Wlh4NnZiQ2d4cHdhRGF4S1lkVUtHR185bVduQWNCNnA0YjVNWSIsInkiOiJQN1c2RFNGRV9aQTZBS1dfTEE5cE4zSFlPb1ZrUlJ1UjNublU1RzdRZmxNIn0",
    "issuanceDate": "2010-01-01T19:23:24Z",
    "credentialSubject":
    {
		"allow":true
    }
}`

var credentialInvalidSubjectID = `
{
    "@context":
    [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
        "https://schema.org"
    ],
    "type": "VerifiableCredential",
    "issuer": "did:jwk:eyJjcnYiOiJQLTI1NiIsImtpZCI6ImVja2V5Iiwia3R5IjoiRUMiLCJ4IjoiNzhqejE4Wlh4NnZiQ2d4cHdhRGF4S1lkVUtHR185bVduQWNCNnA0YjVNWSIsInkiOiJQN1c2RFNGRV9aQTZBS1dfTEE5cE4zSFlPb1ZrUlJ1UjNublU1RzdRZmxNIn0",
    "issuanceDate": "2010-01-01T19:23:24Z",
    "credentialSubject":
    {
      "allow":true,
      "id":"invalid"
    }
}`

var sdJwtCredential = `
{
    "@context":
    [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
        "https://schema.org"
    ],
    "type": ["VerifiableCredential"],
    "issuer": "did:jwk:eyJjcnYiOiJQLTI1NiIsImtpZCI6ImVja2V5Iiwia3R5IjoiRUMiLCJ4IjoiNzhqejE4Wlh4NnZiQ2d4cHdhRGF4S1lkVUtHR185bVduQWNCNnA0YjVNWSIsInkiOiJQN1c2RFNGRV9aQTZBS1dfTEE5cE4zSFlPb1ZrUlJ1UjNublU1RzdRZmxNIn0",
    "issuanceDate": "2010-01-01T19:23:24Z",
    "credentialSubject":
    {
      "allow":true,
      "id":"invalid",
      "vct":"test"
    }
 
}`

var credentialWithNumericalSubjectID = `
{
    "@context":
    [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
        "https://schema.org"
    ],
    "type": ["VerifiableCredential"],
    "issuer": "did:jwk:eyJjcnYiOiJQLTI1NiIsImtpZCI6ImVja2V5Iiwia3R5IjoiRUMiLCJ4IjoiNzhqejE4Wlh4NnZiQ2d4cHdhRGF4S1lkVUtHR185bVduQWNCNnA0YjVNWSIsInkiOiJQN1c2RFNGRV9aQTZBS1dfTEE5cE4zSFlPb1ZrUlJ1UjNublU1RzdRZmxNIn0",
    "issuanceDate": "2010-01-01T19:23:24Z",
    "credentialSubject":
    {
      "allow":true,
      "id":123
    }
}`
