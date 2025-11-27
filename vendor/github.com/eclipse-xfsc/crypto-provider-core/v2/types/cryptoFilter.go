package types

import (
	"regexp"

	pb "github.com/eclipse-xfsc/crypto-provider-core/v2/types/proto"
)

type CryptoFilter struct {
	Id            string
	Filter        regexp.Regexp
	CryptoContext CryptoContext
}

func FromProtoFilter(p *pb.CryptoFilter) CryptoFilter {
	if p == nil {
		return CryptoFilter{}
	}

	re, _ := regexp.Compile(p.Filter)

	return CryptoFilter{
		Id:            p.Id,
		Filter:        *re,
		CryptoContext: FromProtoContext(p.Ctx),
	}
}

func ToProtoFilter(t CryptoFilter) *pb.CryptoFilter {
	return &pb.CryptoFilter{
		Id:     t.Id,
		Filter: t.Filter.String(),
		Ctx:    ToProtoContext(t.CryptoContext),
	}
}
