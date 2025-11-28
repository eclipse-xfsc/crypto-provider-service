package messaging

import (
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
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
