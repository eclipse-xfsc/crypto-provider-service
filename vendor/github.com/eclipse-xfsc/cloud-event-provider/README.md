# Introduction

This library is used for abstracting messaging. The purpose of this library shall be to decapsulate message bus technologies from their usage. So it's doesnt matter if nats, kafka or anything else supported is used. 


# Usage

## Get started

Add the module as dependency using go mod:

`go get github.com/eclipse-xfsc/cloud-event-provider`

And import the module in your code:

```go
import "github.com/eclipse-xfsc/cloud-event-provider"
```

## Configure protocol and corresponding config with yaml File
```yaml
messaging:
  protocol: nats
  nats:
    url: http://localhost:4222
    queueGroup: logger #optional
    timeoutInSec: 10 #optional
```

EnvConfig can also be used by tagging the config: 

```go
Nats      cloudeventprovider.NatsConfig `envconfig:"NATS"`

```

And using ENVs like NATS_REQUEST_TIMEOUT (e.g. 10s), NATS_URL, NATS_QUEUE_GROUP

## Send an Cloudevent
```go
type message struct {
    Receiver string `json:"receiver"`
    Text string `json:"text"`
}

func main() {
    topic := "events"
    client, err := cloudeventprovider.New(cloudeventprovider.Config{
		Protocol: cloudeventprovider.ProtocolTypeNats,
		Settings: cloudeventprovider.NatsConfig{
			Url:          config.Nats.Url,
			QueueGroup:   config.Nats.QueueGroup,
			TimeoutInSec: config.Nats.TimeoutInSec,
		},
	}, cloudeventprovider.Pub, retrieval.TopicRetrevialPublication)

	if err != nil {
		return err
	}
    defer c.Close()

    pubMessage := message{
        Receiver: "Timo",
        Text:     "Hello, my friend",
    }

    data, err := json.Marshal(pubMessage)
    if err != nil {
        log.Fatal(err)
    }
    event, err := cloudeventprovider.NewEvent("event", retrieval.EventTypeRetrievalReceivedNotification, b)
    if err != nil {
        log.Fatal(err)
    }

    if err := c.Pub(event); err != nil {
        log.Fatalf("failed to send, %v", err)
    }
}
```

## Receive an Cloudevent
```go
func StartMessageSubscription(log *logPkg.Logger) {
	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Done()
	log.Info("start messaging!")

	client, err := cloudeventprovider.New(cloudeventprovider.Config{
		Protocol: cloudeventprovider.ProtocolTypeNats,
		Settings: cloudeventprovider.NatsConfig{
			Url:          config.Nats.Url,
			QueueGroup:   config.Nats.QueueGroup,
			TimeoutInSec: config.Nats.TimeoutInSec,
		},
	}, cloudeventprovider.Sub, config.OfferingTopic)
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	defer func() {
		if err := client.Close(); err != nil {
			log.Error(err, "error while closing client")
			os.Exit(1)
		}
	}()

	err = client.Sub(handleMessage)
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}
	wg.Wait()
}
```
## Supported protocols
- Nats
- NatsJetstream
- Kafka
- Http
- Mqtt
- Amqp

## Trouble Shooting

Nats Timeout: If a nats time out error is arising during the sending of a message, check if the handler function was beforehand crashed by an fatal exception. In this case the responder is on the nats bus, but the handler is broken.
