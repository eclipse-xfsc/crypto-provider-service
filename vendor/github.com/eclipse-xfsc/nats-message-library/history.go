package messaging

import "github.com/eclipse-xfsc/nats-message-library/common"

type HistoryRecord struct {
	common.Reply
	UserId  string `json:"user_id"`
	Message string `json:"message"`
}

type RecordEventType string

const (
	Consent             RecordEventType = "consent"
	Pairing             RecordEventType = "pairing"
	Issued              RecordEventType = "issued"
	Presented           RecordEventType = "presented"
	Revoked             RecordEventType = "revoked"
	PresentationRequest RecordEventType = "presentationRequest"
	DeviceConnection    RecordEventType = "device.connection"
)

func RecordEventTypes() []RecordEventType {
	return []RecordEventType{Consent, Pairing, Issued, Presented, Revoked, PresentationRequest, DeviceConnection}
}
