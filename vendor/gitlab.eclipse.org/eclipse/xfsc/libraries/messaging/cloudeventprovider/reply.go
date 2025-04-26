package cloudeventprovider

import (
	"bytes"
	"context"
	"io"
	"log"
	"sync"

	cenats "github.com/cloudevents/sdk-go/protocol/nats/v2"
	"github.com/cloudevents/sdk-go/v2/binding"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/nats-io/nats.go"
)

type natsReplyConsumerInterface interface {
	Reply(ctx context.Context, responseFunction func(ctx context.Context, event event.Event) (*event.Event, error)) error
	Close(ctx context.Context) error
}

type natsReceiver struct {
	incoming chan *nats.Msg
}

func newNatsReceiver() *natsReceiver {
	return &natsReceiver{
		incoming: make(chan *nats.Msg),
	}
}

func (r *natsReceiver) MsgHandler(msg *nats.Msg) {
	r.incoming <- msg
}

type natsRespondConsumer struct {
	natsReceiver
	Conn          *nats.Conn
	Subject       string
	QueueGroup    string
	subMtx        sync.Mutex
	internalClose chan int
	connOwned     bool
}

func newNatsRespondConsumer(url string, subject string, queueGroup string, natsOptions ...nats.Option) (*natsRespondConsumer, error) {
	conn, err := nats.Connect(url, natsOptions...)
	if err != nil {
		return nil, err
	}

	r := &natsRespondConsumer{
		natsReceiver:  *newNatsReceiver(),
		Conn:          conn,
		Subject:       subject,
		QueueGroup:    queueGroup,
		internalClose: make(chan int),
		connOwned:     true,
	}

	return r, nil
}

func (c *natsRespondConsumer) Reply(ctx context.Context, responseFunction func(ctx context.Context, event event.Event) (*event.Event, error)) error {
	c.subMtx.Lock()
	defer c.subMtx.Unlock()

	// Subscribe
	var sub *nats.Subscription
	var err error

	if c.QueueGroup != "" {
		sub, err = c.Conn.QueueSubscribe(c.Subject, c.QueueGroup, c.MsgHandler)
	} else {
		sub, err = c.Conn.Subscribe(c.Subject, c.MsgHandler)
	}
	if err != nil {
		return err
	}

	ctxResponding, cancelResponding := context.WithCancel(ctx)
	go c.ReplyToMessages(ctxResponding, responseFunction)

	// Wait until external or internal context done
	select {
	case <-ctx.Done():
	case <-c.internalClose:
	}

	// Finish to consume messages in the queue
	err = sub.Drain()
	cancelResponding()

	return err
}

// ReplyToMessages is async func to work on incoming messages
func (c *natsRespondConsumer) ReplyToMessages(ctx context.Context, replyFunction func(ctx context.Context, event event.Event) (*event.Event, error)) {
	//TODO: maybe not super efficient to let one thread work on all messages
	for {
		select {
		case msg, ok := <-c.incoming:
			if !ok {
				log.Printf("error occured while reading message from incoming channel: %v", io.EOF)
			}

			incomingEvent, err := binding.ToEvent(ctx, cenats.NewMessage(msg))
			if err != nil {
				log.Printf("error while parse message to event: %v", err)
			}

			respEvent, err := replyFunction(ctx, *incomingEvent)
			if err != nil {
				log.Printf("error while using replyFunction: %v", err)
			}

			respBytes, err := parseEventToBytes(ctx, respEvent)
			if err != nil {
				log.Printf("error while parsing events to bytes: %v", err)
			}

			err = msg.Respond(respBytes)
			if err != nil {
				log.Printf("error while sending response: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (c *natsRespondConsumer) Close(ctx context.Context) error {
	c.internalClose <- 0
	c.subMtx.Lock()
	defer c.subMtx.Unlock()

	if c.connOwned {
		c.Conn.Close()
	}

	close(c.internalClose)

	return nil
}

func parseEventToBytes(ctx context.Context, respEvent *event.Event) ([]byte, error) {
	respMessage := binding.ToMessage(respEvent)

	writer := new(bytes.Buffer)
	if err := cenats.WriteMsg(ctx, respMessage, writer); err != nil {
		return nil, err
	}
	return writer.Bytes(), nil
}
