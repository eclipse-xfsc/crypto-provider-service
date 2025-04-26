package messaging

import "gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/libraries/messaging/common"

const (
	StorePresentationType = "storage.service.presentation"
	StoreCredentialType   = "storage.service.credential"
	StorageTopic          = "storage.service.store"
)

type StorageServiceStoreMessage struct {
	common.Request
	AccountId   string `json:"accountId"`
	Type        string `json:"type"`
	Payload     []byte `json:"payload"`
	ContentType string `json:"contentType"`
	Id          string `json:"id"`
}
