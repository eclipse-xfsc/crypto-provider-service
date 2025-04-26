// Package verify provides a list of additional credential and presentation verifiers.
package verify

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/eclipse-xfsc/crypto-provider-service/internal/service/signer"
	"github.com/eclipse-xfsc/crypto-provider-service/internal/verify/train"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/golib/errors"
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
				return nil, errors.New("error initializing train verifier", err)
			}

			verifiers = append(verifiers, t)
		default:
			return nil, errors.New(errors.Internal, fmt.Sprintf("unknown credential verifier %s", v))
		}
	}

	return verifiers, nil
}
