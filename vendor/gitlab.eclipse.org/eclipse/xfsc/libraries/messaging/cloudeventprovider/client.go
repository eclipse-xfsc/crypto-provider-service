package cloudeventprovider

import (
	"context"
	"errors"
	"fmt"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/client"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/cloudevents/sdk-go/v2/protocol"
)

type CloudEventProviderClient struct {
	context          context.Context
	protocol         ProtocolType
	conn             cloudEventConnection
	connectionClient client.Client
	connectionType   ConnectionType
	alive            bool
}

var ErrInvalidConfig = errors.New("invalid config (type of Config.Settings does not match Config.Protocol)")

// newClient ignores topic parameter for http connections
func newClient(conf Config, connectionType ConnectionType, topic string) (*CloudEventProviderClient, error) {
	ctx := context.Background()

	if conf.Settings == nil {
		return nil, errors.New("Config.Settings is nil")
	}

	var connection interface{}
	var err error

	if conf.Protocol == ProtocolTypeHttp {
		httpConfig, ok := conf.Settings.(HttpConfig)
		if !ok {
			return nil, ErrInvalidConfig
		}

		switch connectionType {
		case ConnectionTypePub, ConnectionTypeReq:
			connection, err = cloudevents.NewHTTP(cloudevents.WithTarget(httpConfig.Url))
		case ConnectionTypeSub, ConnectionTypeRep:
			connection, err = cloudevents.NewHTTP(cloudevents.WithPort(httpConfig.Port), cloudevents.WithPath("/"+httpConfig.Path))
		default:
			return nil, fmt.Errorf("unknown connectionType: %s. Could not create HttpConnection", connectionType)
		}
	} else {
		connection, err = newCloudEventConnection(conf, connectionType, topic)
	}

	if err != nil {
		return nil, err
	}

	connectionClient, err := cloudevents.NewClient(connection)
	if err != nil {
		return nil, err
	}

	// if http cloudEventConnection = nil
	cloudEventConnection, _ := connection.(cloudEventConnection)

	return &CloudEventProviderClient{
		context:          ctx,
		protocol:         conf.Protocol,
		conn:             cloudEventConnection,
		connectionClient: connectionClient,
		connectionType:   connectionType,
		alive:            true,
	}, nil
}

func (c *CloudEventProviderClient) Close() error {
	//TODO: what about closing http?
	if c.protocol == ProtocolTypeHttp {
		return nil
	}

	if err := c.conn.Close(c.context); err != nil {
		return err
	}

	c.alive = false
	return nil
}

func (c *CloudEventProviderClient) Alive() bool {
	return c.alive
}

// Pub publishes the given event.Event
// DEPRECATED: Use PubCtx
func (c *CloudEventProviderClient) Pub(event event.Event) error {
	return c.PubCtx(context.TODO(), event)
}

// PubCtx publishes the given event.Event
func (c *CloudEventProviderClient) PubCtx(ctx context.Context, event event.Event) error {
	if c.connectionType != ConnectionTypePub {
		return fmt.Errorf("pub is not supported for connectionType %s", c.connectionType)
	}

	result := c.connectionClient.Send(ctx, event)
	if err := getResultError(result); err != nil {
		return err
	}

	return nil
}

// Sub Subscribes the client and calls the given fn on receive
// DEPRECATED: Use SubCtx
func (c *CloudEventProviderClient) Sub(fn func(event event.Event)) error {
	return c.SubCtx(context.TODO(), fn)
}

// SubCtx Subscribes the client and calls the given fn on receive
func (c *CloudEventProviderClient) SubCtx(ctx context.Context, fn func(event event.Event)) error {
	if c.connectionType != ConnectionTypeSub {
		return fmt.Errorf("sub is not supported for connectionType %s", c.connectionType)
	}

	return c.connectionClient.StartReceiver(ctx, fn)
}

// Request sends the given event.Event as a request and returns the response
// DEPRECATED: Use RequestCtx
func (c *CloudEventProviderClient) Request(event event.Event, timeOut time.Duration) (*event.Event, error) {
	ctx, cancelFn := context.WithTimeout(context.TODO(), timeOut)
	defer cancelFn()

	return c.RequestCtx(ctx, event)
}

// RequestCtx sends the given event.Event as a request and returns the response
func (c *CloudEventProviderClient) RequestCtx(ctx context.Context, event event.Event) (*event.Event, error) {
	if c.connectionType != ConnectionTypeReq {
		return nil, fmt.Errorf("request is not supported for connectionType %s", c.connectionType)
	}

	response, result := c.connectionClient.Request(ctx, event)
	if err := getResultError(result); err != nil {
		return nil, err
	}

	return response, nil
}

// Reply method is blocking. Use it in a goroutine
// DEPRECATED: Use ReplyCtx
func (c *CloudEventProviderClient) Reply(responseFunc func(ctx context.Context, event event.Event) (*event.Event, error)) error {
	return c.ReplyCtx(context.TODO(), responseFunc)
}

// ReplyCtx method is blocking. Use it in a goroutine
func (c *CloudEventProviderClient) ReplyCtx(ctx context.Context, responseFunc func(ctx context.Context, event event.Event) (*event.Event, error)) error {
	if c.connectionType != ConnectionTypeRep {
		return fmt.Errorf("reply is not supported for connectionType %s", c.connectionType)
	}

	switch c.protocol {
	case ProtocolTypeHttp:
		return c.connectionClient.StartReceiver(ctx, responseFunc)
	case ProtocolTypeNats:
		natsReplyConsumer, ok := c.conn.(natsReplyConsumerInterface)
		if !ok {
			return fmt.Errorf("reply is not supported for connectionType %s", c.connectionType)
		}

		return natsReplyConsumer.Reply(ctx, responseFunc)
	default:
		return fmt.Errorf("reply is not supported for protocol %s", c.protocol)
	}
}

func getResultError(result protocol.Result) error {
	if cloudevents.IsUndelivered(result) {
		return fmt.Errorf("failed to send event: %w", result)
	} else if cloudevents.IsNACK(result) {
		return fmt.Errorf("failed to publish event, event not ack: %w", result)
	} else {
		return nil
	}
}
