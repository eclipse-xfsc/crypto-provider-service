package messaging

import (
	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/credential"
	"gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/libraries/messaging/common"
)

const SourceWellKnownService = "wellknown"

const (
	TopicGetIssuerMetadata     = "wellknown.issuer.metadata"
	EventTypeGetIssuerMetadata = "wellknown.issuer.metadata"
)

type GetIssuerMetadataReq struct {
	common.Request
	Format *string
}

type GetIssuerMetadataReply struct {
	common.Reply
	Issuer *credential.IssuerMetadata
}

const (
	TopicIssuerRegistration     = "wellknown.issuer.registration"
	EventTypeIssuerRegistration = "wellknown.issuer.registration"
)

type IssuerRegistration struct {
	common.Request
	Issuer credential.IssuerMetadata `json:"issuer"`
}
