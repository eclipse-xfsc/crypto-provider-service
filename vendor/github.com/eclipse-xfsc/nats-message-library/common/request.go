package common

import (
	"crypto/sha256"
	"encoding/hex"
)

type Request struct {
	TenantId  string `json:"tenant_id"`
	RequestId string `json:"request_id"`
	GroupId   string `json:"group_id,omitempty"`
}

func (req *Request) BuildSubject() string {
	s := req.TenantId + ";" + req.GroupId + ";" + req.RequestId + ";"

	h := sha256.New()

	h.Write([]byte(s))

	bs := h.Sum(nil)

	return hex.EncodeToString(bs)
}
