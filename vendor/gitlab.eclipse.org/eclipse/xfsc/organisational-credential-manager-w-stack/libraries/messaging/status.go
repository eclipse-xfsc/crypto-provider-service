package messaging

import "gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/libraries/messaging/common"

const (
	EventTypeStatus       = "status.data"
	TopicStatusData       = "status.data.create"
	TopicStatusDataVerify = "status.data.verify"
)

type CreateStatusListEntryRequest struct {
	common.Request
	Origin string `json:"origin"`
}

type CreateStatusListEntryReply struct {
	common.Reply
	Index     int    `json:"index"`
	StatusUrl string `json:"statusUrl"`
	Type 	  string `json:"type"`
	Purpose   string `json:"purpose"`
}

type VerifyStatusListEntryRequest struct {
	common.Request
	Index         int    `json:"index"`
	StatusUrl     string `json:"statusUrl"`
	Type 	      string `json:"type"`
	Purpose       string `json:"purpose"`
}

type VerifyStatusListEntryReply struct {
	common.Reply
	Revocated bool `json:"revocated"`
	Suspended bool `json:"suspended"`
}
