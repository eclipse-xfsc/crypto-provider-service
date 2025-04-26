package main

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/google/uuid"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/messaging/cloudeventprovider"
	msg "gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/libraries/messaging"
	"gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/libraries/messaging/common"
)

func main() {

	var err error

	reqClient, err := cloudeventprovider.New(cloudeventprovider.Config{
		Protocol: cloudeventprovider.ProtocolTypeNats,
		Settings: cloudeventprovider.NatsConfig{
			Url:          "nats://127.0.0.1:4222",
			QueueGroup:   "",
			TimeoutInSec: time.Hour,
		},
	}, cloudeventprovider.Req, "signer-topic")

	if err != nil {
		return
	}

	var p = make(map[string]interface{})
	p["nonce"] = "34r5"

	pb, err := json.Marshal(p)

	var req = msg.CreateTokenRequest{
		Request: common.Request{
			TenantId:  "3434",
			RequestId: uuid.NewString(),
		},
		Namespace: "transit",
		Key:       "eckey",
		Payload:   pb,
	}

	js, err := json.Marshal(req)

	ev, err := cloudeventprovider.NewEvent("request", "signer.signToken", js)

	reader := bufio.NewReader(os.Stdin)

	for {
		ev, err := reqClient.RequestCtx(context.Background(), ev)

		if err != nil {
			println(err.Error())
			break
		}

		println("Type: " + ev.Type())

		var rep msg.CreateTokenReply

		err = json.Unmarshal(ev.DataEncoded, &rep)

		if err != nil {
			println(err.Error())
			break
		}

		println("Token: " + string(rep.Token))
		reader.ReadString('\n')
	}

}
