package credential

var (
	ErrInvalidCredentialRequest    = CredentialErrorResponse{ErrorMsg: InvalidCredentialRequest}
	ErrUnsupportedCredentialType   = CredentialErrorResponse{ErrorMsg: UnsupportedCredentialType}
	ErrUnsupportedCredentialFormat = CredentialErrorResponse{ErrorMsg: UnsupportedCredentialFormat}
	ErrInvalidProof                = CredentialErrorResponse{ErrorMsg: InvalidProof}
	ErrInvalidEncryptionParameters = CredentialErrorResponse{ErrorMsg: InvalidEncryptionParameters}
)

func (e CredentialErrorResponse) Error() string {
	return e.ErrorMsg
}

type CredentialErrorResponse struct {
	ErrorMsg  string  `json:"error"`
	ErrorDesc *string `json:"error_description,omitempty"`
}

const (
	//	Credential Error Options
	InvalidCredentialRequest    = "invalid_credential_request"
	UnsupportedCredentialType   = "unsupported_credential_type"
	UnsupportedCredentialFormat = "unsupported_credential_format"
	InvalidProof                = "invalid_proof"
	InvalidEncryptionParameters = "invalid_encryption_parameters"
)

type CredentialResponse struct {
	Format          string      `json:"format"`
	Credential      interface{} `json:"credential,omitempty"`
	TransactionID   string      `json:"transaction_id,omitempty"`
	CNonce          string      `json:"c_nonce,omitempty"`
	CNonceExpiresIn int         `json:"c_nonce_expires_in,omitempty"`
	NotificationId  string      `json:"notification_id,omitempty"`
}

type CredentialResponseError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
