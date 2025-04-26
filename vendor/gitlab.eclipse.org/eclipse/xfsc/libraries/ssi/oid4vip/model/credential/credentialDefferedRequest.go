package credential

const (
	InvalidTransactionId = "invalid_transaction_id"
	IssuancePending      = "issuance_pending"
)

type CredentialDeferredRequest struct {
	TransactionID string `json:"transaction_id"`
}
