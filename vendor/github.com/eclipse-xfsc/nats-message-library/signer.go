package messaging

import "github.com/eclipse-xfsc/nats-message-library/common"

const (
	SignerServiceCreateKeyType string = "signer.createKey"
	SignerServiceSignTokenType string = "signer.signToken"
	SignerServiceErrorType     string = "signer.error"
)

type CreateKeyRequest struct {
	common.Request
	Namespace string `json:"namespace"`
	Group     string `json:"group"`
	Key       string `json:"key"`
	Type      string `json:"type"`
}

type CreateKeyReply struct {
	common.Reply
}

type CreateTokenRequest struct {
	common.Request
	Namespace string `json:"namespace"`
	Group     string `json:"group"`
	Key       string `json:"key"`
	Payload   []byte `json:"payload"`
	Header    []byte `json:"header"`
}

type CreateTokenReply struct {
	common.Reply
	Token []byte `json:"token"`
}
