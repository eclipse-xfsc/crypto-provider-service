package common

type Request struct {
	TenantId  string `json:"tenant_id"`
	RequestId string `json:"request_id"`
	GroupId   string `json:"group_id,omitempty"`
}
