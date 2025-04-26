package messaging

import (
	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/credential"
	"gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/libraries/messaging/common"
)

const (
	EventTypeIssuance = "issuance.request"
)

type IssuanceRequest struct {
	common.Request
	Identifier string                 `json:"identifier"`
	Payload    map[string]interface{} `json:"payload"`
}

type IssuanceReply struct {
	common.Reply
	Offer credential.CredentialOffer `json:"offer"`
}
