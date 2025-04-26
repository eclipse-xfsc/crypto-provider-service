package cloudeventprovider

import (
	"bytes"
	"context"
	"log"
	"time"

	cenats "github.com/cloudevents/sdk-go/protocol/nats/v2"
	"github.com/cloudevents/sdk-go/v2/binding"
	"github.com/nats-io/nats.go"
)

type natsRequester struct {
	Conn      *nats.Conn
	Subject   string
	connOwned bool
	timeOut   time.Duration
}

func newNatsRequester(url string, subject string, natsOptions ...nats.Option) (*natsRequester, error) {
	conn, err := nats.Connect(url, natsOptions...)
	if err != nil {
		return nil, err
	}

	r := &natsRequester{
		Conn:      conn,
		Subject:   subject,
		connOwned: true,
		timeOut:   10 * time.Second,
	}

	return r, nil
}

func (r *natsRequester) Request(ctx context.Context, m binding.Message, transformers ...binding.Transformer) (binding.Message, error) {
	writer := new(bytes.Buffer)
	if err := cenats.WriteMsg(ctx, m, writer, transformers...); err != nil {
		return nil, err
	}

	var timeout = r.timeOut
	if deadline, isSet := ctx.Deadline(); isSet {
		timeout = deadline.Sub(time.Now())
	}

	natsMsg, err := r.Conn.Request(r.Subject, writer.Bytes(), timeout)
	if err != nil {
		if r.Conn.LastError() != nil {
			log.Fatalf("%v for request", r.Conn.LastError())
		}
		return nil, err
	}

	return cenats.NewMessage(natsMsg), nil
}

func (r *natsRequester) Close(ctx context.Context) error {
	if r.connOwned {
		r.Conn.Close()
	}

	return nil
}
