package messaging

import (
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
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
