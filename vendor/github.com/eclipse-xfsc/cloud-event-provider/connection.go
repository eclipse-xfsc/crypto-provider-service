package cloudeventprovider

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/go-amqp"
	"github.com/IBM/sarama"
	ceamqp "github.com/cloudevents/sdk-go/protocol/amqp/v2"
	kafkaSarama "github.com/cloudevents/sdk-go/protocol/kafka_sarama/v2"
	mqttPaho "github.com/cloudevents/sdk-go/protocol/mqtt_paho/v2"
	cenats "github.com/cloudevents/sdk-go/protocol/nats/v2"
	cejsm "github.com/cloudevents/sdk-go/protocol/nats_jetstream/v2"
	"github.com/eclipse/paho.golang/paho"
	"github.com/nats-io/nats.go"
)

type cloudEventConnection interface {
	Close(ctx context.Context) error
}

func newCloudEventConnection(conf Config, connectionType ConnectionType, topic string) (cloudEventConnection, error) {
	switch conf.Protocol {
	case ProtocolTypeKafka:
		return newKafkaConnection(conf.Settings.(KafkaConfig), connectionType, topic)
	case ProtocolTypeNats:
		return newNatsConnection(conf.Settings.(NatsConfig), connectionType, topic)
	case ProtocolTypeNatsJetstream:
		return newNatsJetstreamConnection(conf.Settings.(NatsJetstreamConfig), connectionType, topic)
	case ProtocolTypeMqtt:
		return newMqttConnection(conf.Settings.(MqttConfig), connectionType, topic)
	case ProtocolTypeAmqp:
		return newAmqpConnection(conf.Settings.(AmqpConfig), connectionType, topic)
	}

	return nil, fmt.Errorf("unknown protocolType: %s. Could not create cloudEventConnection", conf.Protocol)
}

func newKafkaConnection(conf KafkaConfig, connectionType ConnectionType, topic string) (cloudEventConnection, error) {
	saramaConfig := sarama.NewConfig()
	saramaConfig.Version = sarama.V2_0_0_0

	switch connectionType {
	case ConnectionTypePub:
		return kafkaSarama.NewSender([]string{conf.Url}, saramaConfig, topic)
	case ConnectionTypeSub:
		return kafkaSarama.NewConsumer([]string{conf.Url}, saramaConfig, conf.GroupId, topic)
	}

	return nil, fmt.Errorf("unknown connectionType: %s. Could not create KafkaConnection", connectionType)
}

func newNatsConnection(conf NatsConfig, connectionType ConnectionType, topic string) (cloudEventConnection, error) {
	var natsOptions []nats.Option
	if conf.TimeoutInSec != 0*time.Second {
		natsOptions = append(natsOptions, nats.Timeout(conf.TimeoutInSec))
	}

	switch connectionType {
	case ConnectionTypePub:
		return cenats.NewSender(conf.Url, topic, natsOptions)
	case ConnectionTypeSub:
		consumerOptions := make([]cenats.ConsumerOption, 0)
		if conf.QueueGroup != "" {
			consumerOptions = append(consumerOptions, cenats.WithQueueSubscriber(conf.QueueGroup))
		}

		return cenats.NewConsumer(conf.Url, topic, natsOptions, consumerOptions...)
	case ConnectionTypeReq:
		return newNatsRequester(conf.Url, topic, natsOptions...)
	case ConnectionTypeRep:
		return newNatsRespondConsumer(conf.Url, topic, conf.QueueGroup, natsOptions...)
	}

	return nil, fmt.Errorf("unknown connectionType: %s. Could not create NatsConnection", connectionType)
}

func newNatsJetstreamConnection(conf NatsJetstreamConfig, connectionType ConnectionType, topic string) (cloudEventConnection, error) {
	var natsJetstreamOptions []nats.Option
	if conf.TimeoutInSec != 0 {
		natsJetstreamOptions = []nats.Option{nats.Timeout(conf.TimeoutInSec * time.Second)}
	}

	switch connectionType {
	case ConnectionTypePub:
		return cejsm.NewSender(conf.Url, conf.StreamType, topic, natsJetstreamOptions, nil)
	case ConnectionTypeSub:
		var consumerOption cejsm.ConsumerOption
		if conf.QueueGroup != "" {
			consumerOption = cejsm.WithQueueSubscriber(conf.QueueGroup)
		}

		return cejsm.NewConsumer(conf.Url, conf.StreamType, topic, natsJetstreamOptions, nil, nil, consumerOption)
	}

	return nil, fmt.Errorf("unknown connectionType: %s. Could not create NatsJetstreamConnection", connectionType)
}

func newMqttConnection(conf MqttConfig, connectionType ConnectionType, topic string) (cloudEventConnection, error) {
	ctx := context.Background()

	conn, err := net.Dial("tcp", conf.Url)
	if err != nil {
		return nil, err
	}

	switch connectionType {
	case ConnectionTypePub:
		connectionConfig := &paho.ClientConfig{
			ClientID: conf.ClientId,
			Conn:     conn,
		}
		// optional connect option
		connOpt := &paho.Connect{
			KeepAlive:  30,
			CleanStart: true,
		}

		sender, err := mqttPaho.New(ctx, connectionConfig, mqttPaho.WithPublish(&paho.Publish{Topic: topic}), mqttPaho.WithConnect(connOpt))
		if err != nil {
			return nil, err
		}
		return sender, nil
	case ConnectionTypeSub:
		connectionConfig := &paho.ClientConfig{
			ClientID: conf.ClientId,
			Conn:     conn,
		}
		subscribeOpt := &paho.Subscribe{
			Subscriptions: []paho.SubscribeOptions{
				{
					Topic: topic,
					QoS:   0,
				},
			},
		}

		consumer, err := mqttPaho.New(ctx, connectionConfig, mqttPaho.WithSubscribe(subscribeOpt))
		if err != nil {
			return nil, err
		}
		return consumer, nil
	default:
		return nil, fmt.Errorf("unknown connectionType: %s. Could not create MqttConnection", connectionType)
	}
}

func newAmqpConnection(conf AmqpConfig, connectionType ConnectionType, topic string) (cloudEventConnection, error) {
	if connectionType != ConnectionTypeSub && connectionType != ConnectionTypePub {
		return nil, fmt.Errorf("unknown connectionType: %s. Could not create AmqpConnection", connectionType)
	}

	amqpUrl, node, opts := parseAmqpConfig(conf)

	if topic != "" {
		return ceamqp.NewProtocol(amqpUrl, topic, nil, nil, opts...)
	}

	return ceamqp.NewProtocol(amqpUrl, node, nil, nil, opts...)
}

func parseAmqpConfig(conf AmqpConfig) (string, string, []ceamqp.Option) {
	// TODO: authentication over URL is not safe!
	parsedUrl, err := url.Parse(conf.Url)
	if err != nil {
		log.Fatal(err)
	}

	if parsedUrl.User == nil {
		return conf.Url, strings.TrimPrefix(parsedUrl.Path, "/"), nil
	}

	user := parsedUrl.User.Username()
	pass, _ := parsedUrl.User.Password()

	return conf.Url,
		strings.TrimPrefix(parsedUrl.Path, "/"),
		[]ceamqp.Option{ceamqp.WithConnOpt(amqp.ConnSASLPlain(user, pass))}
}
