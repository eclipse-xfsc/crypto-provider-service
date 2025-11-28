package common

type Reply struct {
	TenantId  string `json:"tenant_id"`
	RequestId string `json:"request_id"`
	GroupId   string `json:"group_id,omitempty"`
	Error     *Error `json:"error"`
}

type Error struct {
	Status int    `json:"status"`
	Id     string `json:"id"`
	Msg    string `json:"msg"`
}
