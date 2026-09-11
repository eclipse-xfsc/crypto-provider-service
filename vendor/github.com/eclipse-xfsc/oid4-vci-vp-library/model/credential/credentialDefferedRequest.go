package credential

type CredentialDeferredRequest struct {
	TransactionID string `json:"transaction_id"`

	CredentialResponseEncryption *CredentialResponseEncryptionParameters `json:"credential_response_encryption,omitempty"`
}
