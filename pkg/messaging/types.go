package messaging

import (
	"gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/libraries/messaging/common"
)

const (
	SignerServiceCreateKeyType string = "signer.createKey"
	SignerServiceSignTokenType string = "signer.signToken"
	SignerServiceSign          string = "signer.sign"
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

type CreateSigningRequest struct {
	common.Request
	Namespace string `json:"namespace"`
	Group     string `json:"group"`
	Key       string `json:"key"`
	Payload   []byte `json:"payload"`
}

type CreateSigningReply struct {
	common.Reply
	Signature []byte `json:"token"`
}
