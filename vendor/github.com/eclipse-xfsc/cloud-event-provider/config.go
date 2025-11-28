package cloudeventprovider

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/spf13/viper"
)

var cloudEventProviderViper *viper.Viper

type Config struct {
	Protocol ProtocolType `mapstructure:"protocol"`
	Settings protocolConfig
}

type protocolConfig interface {
	validate() error
}

type NatsConfig struct {
	Url          string        `mapstructure:"url" envconfig:"URL" default:"127.0.0.1"`
	QueueGroup   string        `mapstructure:"queueGroup,omitempty" envconfig:"QUEUE_GROUP"`
	TimeoutInSec time.Duration `mapstructure:"timeoutInSec,omitempty" envconfig:"REQUEST_TIMEOUT"`
}

func (c NatsConfig) validate() error {
	if c.Url == "" {
		return errors.New("missing value for required field Url")
	}

	return nil
}

type NatsJetstreamConfig struct {
	Url          string        `mapstructure:"url" envconfig:"URL" default:"127.0.0.1"`
	QueueGroup   string        `mapstructure:"queueGroup,omitempty" envconfig:"QUEUE_GROUP"`
	StreamType   string        `mapstructure:"streamType" envconfig:"STREAM_TYPE"`
	TimeoutInSec time.Duration `mapstructure:"timeoutInSec,omitempty" envconfig:"REQUEST_TIMEOUT"`
}

func (c NatsJetstreamConfig) validate() error {
	if c.Url == "" {
		return errors.New("missing value for required field Url")
	}

	if c.StreamType == "" {
		return errors.New("missing value for required field StreamType")
	}

	return nil
}

type KafkaConfig struct {
	Url      string `mapstructure:"url" envconfig:"URL" default:"127.0.0.1"`
	GroupId  string `mapstructure:"groupId,omitempty" envconfig:"GROUP_ID"`
	ClientId string `mapstructure:"clientId" envconfig:"CLIENT_ID"`
}

func (c KafkaConfig) validate() error {
	if c.Url == "" {
		return errors.New("missing value for required field Url")
	}

	if c.ClientId == "" {
		return errors.New("missing value for required field ClientId")
	}

	return nil
}

type MqttConfig struct {
	Url      string `mapstructure:"url" envconfig:"URL" default:"127.0.0.1"`
	ClientId string `mapstructure:"clientId" envconfig:"CLIENT_ID"`
}

func (c MqttConfig) validate() error {
	if c.Url == "" {
		return errors.New("missing value for required field Url")
	}

	if c.ClientId == "" {
		return errors.New("missing value for required field ClientId")
	}

	return nil
}

type AmqpConfig struct {
	Url string `mapstructure:"url" envconfig:"URL" default:"127.0.0.1"`
}

func (c AmqpConfig) validate() error {
	if c.Url == "" {
		return errors.New("missing value for required field Url")
	}

	return nil
}

type HttpConfig struct {
	Url  string `mapstructure:"url" envconfig:"URL" default:"127.0.0.1"`
	Port int    `mapstructure:"port" envconfig:"PORT" default:"8080"`
	Path string `mapstructure:"path" envconfig:"PATH"`
}

func (c HttpConfig) validate() error {
	if c.Url == "" {
		return errors.New("missing value for required field Url")
	}

	if c.Port == 0 {
		return errors.New("missing value for required field Port")
	}

	if c.Path == "" {
		return errors.New("missing value for required field Path")
	}

	return nil
}

type cloudEventProviderConfiguration struct {
	Messaging struct {
		Protocol      ProtocolType        `mapstructure:"protocol" envconfig:"PROTOCOL_TYPE"`
		Nats          NatsConfig          `mapstructure:"nats" envconfig:"NATS"`
		NatsJetstream NatsJetstreamConfig `mapstructure:"natsJetstream" envconfig:"JETSTREAM"`
		Kafka         KafkaConfig         `mapstructure:"kafka" envconfig:"KAFKA"`
		Mqtt          MqttConfig          `mapstructure:"mqtt" envconfig:"MQTT"`
		Amqp          AmqpConfig          `mapstructure:"amqp" envconfig:"AMQP"`
		Http          HttpConfig          `mapstructure:"http" envconfig:"HTTP"`
	} `mapstructure:"messaging" envconfig:"MESSAGING"`
}

func loadConfig() (*Config, error) {
	if err := bindEnvs(); err != nil {
		return nil, err
	}
	readConfig()

	var config cloudEventProviderConfiguration
	if err := cloudEventProviderViper.Unmarshal(&config); err != nil {
		return nil, err
	}

	var proConf protocolConfig
	switch config.Messaging.Protocol {
	case ProtocolTypeHttp:
		proConf = config.Messaging.Http
	case ProtocolTypeNats:
		proConf = config.Messaging.Nats
	case ProtocolTypeNatsJetstream:
		proConf = config.Messaging.NatsJetstream
	case ProtocolTypeAmqp:
		proConf = config.Messaging.Amqp
	case ProtocolTypeMqtt:
		proConf = config.Messaging.Mqtt
	case ProtocolTypeKafka:
		proConf = config.Messaging.Kafka
	default:
		return nil, fmt.Errorf("missing or invalid protocol")
	}

	if err := proConf.validate(); err != nil {
		return nil, err
	}

	conf := Config{
		Protocol: config.Messaging.Protocol,
		Settings: proConf,
	}

	return &conf, nil
}

func bindEnvs() error {
	envs := []string{
		"messaging.protocol",
		"messaging.nats.url",
		"messaging.nats.queueGroup",
		"messaging.nats.timeOutInSec",
		"messaging.natsJetstream.url",
		"messaging.natsJetstream.queueGroup",
		"messaging.natsJetstream.streamType",
		"messaging.natsJetstream.timeOutInSec",
		"messaging.kafka.url",
		"messaging.kafka.groupId",
		"messaging.kafka.clientId",
		"messaging.mqtt.url",
		"messaging.mqtt.clientId",
		"messaging.ampq.url",
		"messaging.ampq.clientId",
		"messaging.http.url",
		"messaging.http.port",
		"messaging.http.path",
	}

	if err := cloudEventProviderViper.BindEnv(envs...); err != nil {
		return fmt.Errorf("could not bind env: %w", err)
	}

	return nil
}

func readConfig() {
	cloudEventProviderViper.SetConfigName("config")
	cloudEventProviderViper.SetConfigType("yaml")
	cloudEventProviderViper.AddConfigPath(".")

	cloudEventProviderViper.SetEnvPrefix("CLOUDEVENTPROVIDER")
	cloudEventProviderViper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := cloudEventProviderViper.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			log.Printf("Configuration not found but environment variables will be taken into account.")
		}

		cloudEventProviderViper.AutomaticEnv()
	}
}
