package types

import (
	"context"

	pb "github.com/eclipse-xfsc/crypto-provider-core/v2/types/proto"
)

type CryptoContext struct {
	Namespace string
	Group     string
	Context   context.Context
	Logger    CryptoLogger
	Engine    string
}

func FromProtoContext(p *pb.CryptoContext) CryptoContext {
	if p == nil {
		return CryptoContext{}
	}

	return CryptoContext{
		Namespace: p.Namespace,
		Group:     p.Group,
		Engine:    p.Engine,

		// RPC überträgt diese nicht – lokale Defaults:
		Context: context.Background(),
		Logger:  nil,
	}
}

func ToProtoContext(t CryptoContext) *pb.CryptoContext {
	return &pb.CryptoContext{
		Namespace: t.Namespace,
		Group:     t.Group,
		Engine:    t.Engine,
	}
}
