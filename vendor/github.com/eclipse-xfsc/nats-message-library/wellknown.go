package messaging

import (
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
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
	TopicIssuerRegistration               = "wellknown.issuer.registration"
	EventTypeIssuerRegistration           = "wellknown.issuer.registration"
	EventTypeIssuerCredentialRegistration = "wellknown.issuer.credential.registration"
)

type IssuerRegistration struct {
	common.Request
	Issuer credential.IssuerMetadata `json:"issuer"`
}

type CredentialRegistration struct {
	common.Request
	Issuer                  string                             `json:"issuer"`
	ConfigurationId         string                             `json:"ConfigurationId"`
	CredentialConfiguration credential.CredentialConfiguration `json:"CredentialConfiguration"`
}
