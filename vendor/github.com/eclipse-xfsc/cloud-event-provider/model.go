package cloudeventprovider

type ProtocolType string

const (
	ProtocolTypeHttp          ProtocolType = "http"
	ProtocolTypeKafka         ProtocolType = "kafka"
	ProtocolTypeNats          ProtocolType = "nats"
	ProtocolTypeNatsJetstream ProtocolType = "natsJetstream"
	ProtocolTypeMqtt          ProtocolType = "mqtt"
	ProtocolTypeAmqp          ProtocolType = "amqp"
)

// Deprecated, use ProtocolType*
const (
	Http          ProtocolType = "http"
	Kafka         ProtocolType = "kafka"
	Nats          ProtocolType = "nats"
	NatsJetstream ProtocolType = "natsJetstream"
	Mqtt          ProtocolType = "mqtt"
	Amqp          ProtocolType = "amqp"
)

type ConnectionType string

const (
	ConnectionTypePub ConnectionType = "pub"
	ConnectionTypeSub ConnectionType = "sub"
	ConnectionTypeReq ConnectionType = "req"
	ConnectionTypeRep ConnectionType = "rep"
)

// Deprecated, use ConnectionType*
const (
	Pub ConnectionType = "pub"
	Sub ConnectionType = "sub"
	Req ConnectionType = "req"
	Rep ConnectionType = "rep"
)
