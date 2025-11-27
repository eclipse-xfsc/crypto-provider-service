package cloudeventprovider

import (
	"context"
	"encoding/json"
	"time"

	"github.com/spf13/viper"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/google/uuid"
)

type CloudEventProvider interface {
	Close() error
	Alive() bool
	Pub(event event.Event) error
	PubCtx(ctx context.Context, event event.Event) error
	Sub(fn func(event event.Event)) error
	SubCtx(ctx context.Context, fn func(event event.Event)) error
	Request(event event.Event, timeOut time.Duration) (*event.Event, error)
	RequestCtx(ctx context.Context, event event.Event) (*event.Event, error)
	Reply(responseFunc func(ctx context.Context, event event.Event) (*event.Event, error)) error
	ReplyCtx(ctx context.Context, responseFunc func(ctx context.Context, event event.Event) (*event.Event, error)) error
}

// New initializes a CloudEventProviderClient using the passed Config. In contrast to NewClient, it
// does not rely on a configuration other than the one provided.
func New(conf Config, conType ConnectionType, topic string) (*CloudEventProviderClient, error) {
	return newClient(conf, conType, topic)
}

// NewClient initializes a CloudEventProviderClient. It uses viper.Viper as the config library and
// might make assumptions about your config.yaml
func NewClient(connectionType ConnectionType, topic string) (*CloudEventProviderClient, error) {
	cloudEventProviderViper = viper.New()

	config, err := loadConfig()
	if err != nil {
		return nil, err
	}

	return newClient(*config, connectionType, topic)
}

// NewEvent initializes an event.Event ready to be submitted
func NewEvent(eventSource string, eventType string, data json.RawMessage) (event.Event, error) {
	newEvent := cloudevents.NewEvent()
	newEvent.SetID(uuid.NewString())
	newEvent.SetSource(eventSource)
	newEvent.SetType(eventType)

	if err := newEvent.SetData(cloudevents.ApplicationJSON, data); err != nil {
		return newEvent, err
	}

	return newEvent, nil
}
