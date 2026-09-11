package credential

import (
	"encoding/json"
)

var (
	ErrInvalidCredentialRequest = CredentialErrorResponse{
		ErrorMsg: InvalidCredentialRequest,
	}

	ErrUnknownCredentialConfiguration = CredentialErrorResponse{
		ErrorMsg: UnknownCredentialConfiguration,
	}

	ErrUnknownCredentialIdentifier = CredentialErrorResponse{
		ErrorMsg: UnknownCredentialIdentifier,
	}

	ErrInvalidProof = CredentialErrorResponse{
		ErrorMsg: InvalidProof,
	}

	ErrInvalidNonce = CredentialErrorResponse{
		ErrorMsg: InvalidNonce,
	}

	ErrInvalidEncryptionParameters = CredentialErrorResponse{
		ErrorMsg: InvalidEncryptionParameters,
	}

	ErrCredentialRequestDenied = CredentialErrorResponse{
		ErrorMsg: CredentialRequestDenied,
	}

	ErrInvalidTransactionID = CredentialErrorResponse{
		ErrorMsg: InvalidTransactionID,
	}
)

func (e CredentialErrorResponse) Error() string {
	if e.ErrorDesc != nil {
		return e.ErrorMsg + ": " + *e.ErrorDesc
	}

	return e.ErrorMsg
}

type CredentialErrorResponse struct {
	ErrorMsg  string  `json:"error"`
	ErrorDesc *string `json:"error_description,omitempty"`
}

const (
	InvalidCredentialRequest = "invalid_credential_request"

	UnknownCredentialConfiguration = "unknown_credential_configuration"

	UnknownCredentialIdentifier = "unknown_credential_identifier"

	InvalidProof = "invalid_proof"

	InvalidNonce = "invalid_nonce"

	InvalidEncryptionParameters = "invalid_encryption_parameters"

	CredentialRequestDenied = "credential_request_denied"

	InvalidTransactionID = "invalid_transaction_id"
)

type CredentialResponse struct {
	// Immediate issuance.
	//
	// Credentials and TransactionID are mutually exclusive.
	Credentials []CredentialResponseItem `json:"credentials,omitempty"`

	// Deferred issuance.
	TransactionID string `json:"transaction_id,omitempty"`

	// Required for a deferred response.
	Interval int `json:"interval,omitempty"`

	// Used with the Notification Endpoint.
	//
	// Only valid when Credentials is present.
	NotificationID string `json:"notification_id,omitempty"`
}

type CredentialResponseItem struct {
	// Depending on the Credential Format, credential may either be
	// a JSON string or a JSON object.
	Credential json.RawMessage `json:"credential"`
}

type CredentialResponseError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}
