// Package verify provides a list of additional credential and presentation verifiers.
package verify

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/eclipse-xfsc/crypto-provider-service/v2/internal/service/signer"
	"github.com/eclipse-xfsc/crypto-provider-service/v2/internal/verify/train"
	pkgErr "github.com/eclipse-xfsc/microservice-core-go/pkg/err"
)

// New initializes a list of signer.Verifier based on the given names.
func New(names []string, httpClient *http.Client, trainAddr string, trainSchemes []string) ([]signer.Verifier, error) {
	var verifiers []signer.Verifier
	for _, v := range names {
		v := strings.ToLower(v)
		switch v {
		case "train":
			t, err := train.New(httpClient, trainAddr, trainSchemes)
			if err != nil {
				return nil, pkgErr.New("error initializing train verifier", err)
			}

			verifiers = append(verifiers, t)
		default:
			return nil, pkgErr.New(pkgErr.Internal, fmt.Sprintf("unknown credential verifier %s", v))
		}
	}

	return verifiers, nil
}
