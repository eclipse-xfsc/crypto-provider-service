package types

import (
	"context"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	cryptoCore "gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/engine/core/types"
)

type SignerInterceptor struct {
	alg            jwa.SignatureAlgorithm
	cryptoProvider cryptoCore.CryptoProvider
}

func (s *SignerInterceptor) CreateInterceptor(
	alg jwa.SignatureAlgorithm,
	cryptoprovider cryptoCore.CryptoProvider, sign bool, verify bool) {
	s.alg = alg
	s.cryptoProvider = cryptoprovider
	if sign {
		jws.RegisterSigner(alg, jws.SignerFactoryFn(s.CreateSignerInterceptor))
	}

	if verify {
		jws.RegisterVerifier(alg, jws.VerifierFactoryFn(s.CreateVerifyInterceptor))
	}
}

func (s *SignerInterceptor) CreateSignerInterceptor() (jws.Signer, error) {
	return s, nil
}

func (s *SignerInterceptor) CreateVerifyInterceptor() (jws.Verifier, error) {
	return s, nil
}

func (s *SignerInterceptor) Algorithm() jwa.SignatureAlgorithm {
	return s.alg
}

func (s *SignerInterceptor) Sign(payload []byte, keyif interface{}) ([]byte, error) {
	return s.cryptoProvider.Sign(s.createParamter(keyif.(string)), payload)
}

func (s *SignerInterceptor) Verify(payload []byte, signature []byte, keyif interface{}) error {
	result, err := s.cryptoProvider.Verify(s.createParamter(keyif.(string)), payload, signature)

	if result {
		return nil
	}
	return err
}

func (s *SignerInterceptor) createParamter(keyId string) cryptoCore.CryptoIdentifier {
	parts := strings.Split(keyId, ":")
	ns := strings.Split(parts[0], "/")
	parameter := cryptoCore.CryptoIdentifier{
		KeyId: parts[1],
		CryptoContext: cryptoCore.CryptoContext{
			Context:   context.Background(),
			Namespace: ns[0],
			Group:     ns[1],
		},
	}

	return parameter
}
