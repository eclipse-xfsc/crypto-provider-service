# cloudevent-provider

## Get started

Add the module as dependency using go mod:

`go get gitlab.eclipse.org/eclipse/xfsc/libraries/messaging/cloudeventprovider`

And import the module in your code:

```go
import "gitlab.eclipse.org/eclipse/xfsc/libraries/messaging/cloudeventprovider"
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

## Send an Cloudevent
```go
type message struct {
    Receiver string `json:"receiver"`
    Text string `json:"text"`
}

func main() {
    topic := "events"
    c, err := cloudeventprovider.NewClient(cloudeventprovider.Pub, topic)
    if err != nil {
        log.Fatal(err)
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
    event, err := cloudeventprovider.CreateEvent("example/uri", "example.type", data)
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
func receive(event event.Event) {
    fmt.Printf("%s", event)
}

func main() {
    topic := "events"
    client, err := cloudeventprovider.NewClient(cloudeventprovider.Sub, topic)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()
    
    log.Fatal(client.Sub(receive))
}
```

## Supported protocols
- Nats
- NatsJetstream
- Kafka
- Http
- Mqtt
- Amqp