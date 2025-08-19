package messaging

import (
	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/credential"
	"gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/libraries/messaging/common"
)

const (
	EventTypeRetrievalExternal               = "retrieval.offering.external"
	EventTypeRetrievalAcceptanceNotification = "retrieval.offering.acceptance"
	EventTypeRetrievalReceivedNotification   = "retrieval.offering.received"
	TopicRetrevialSubscription               = "retrieval.offering.subscription"
	TopicRetrevialPublication                = "retrieval.offering.publication"
)

// Incoming Event for Offerings --> EventTypeRetrievalExternal
type RetrievalOffering struct {
	common.Request
	Offer credential.CredentialOffer `json:"offer"`
}

// Notification when something was received --> EventTypeRetrievalReceivedNotification
type RetrievalNotification struct {
	common.Request
	Offer credential.CredentialOfferParameters `json:"offerParams"`
}

// Notification when something was accepted --> EventTypeRetrievalAcceptanceNotification
type RetrievalAcceptanceNotification struct {
	common.Request
	OfferingId      string `json:"offeringId"`
	Message         string `json:"message"`
	Result          bool   `json:"result"`
	HolderKey       string `json:"holderKey`
	HolderNamespace string `json:"holderNamespace`
	HolderGroup     string `json:"holderGroup`
	TxCode          string `json:"tx_code`
}
