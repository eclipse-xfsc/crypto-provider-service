package jwt

import (
	"context"
	"errors"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	ljwt "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/sirupsen/logrus"
	cryptoCore "gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/engine/core/types"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/jwt/types"
)

var fetchers map[string]types.KeyFetcher = make(map[string]types.KeyFetcher)
var verify = false
var sign = false

func RegisterFetcher(id string, fetcher types.KeyFetcher) {
	fetchers[id] = fetcher
}

func UnregisterFetcher(id string) {
	fetcher, ok := fetchers[id]
	if ok {
		delete(fetchers, id)
		fetcher.Stop()
	}
}

func EnableCryptoProvider(cryptoprovider cryptoCore.CryptoProvider, sign bool, verify bool) {
	sign = sign
	verify = verify
	new(types.SignerInterceptor).CreateInterceptor(jwa.PS256, cryptoprovider, sign, verify)
	new(types.SignerInterceptor).CreateInterceptor(jwa.PS384, cryptoprovider, sign, verify)
	new(types.SignerInterceptor).CreateInterceptor(jwa.PS512, cryptoprovider, sign, verify)
	new(types.SignerInterceptor).CreateInterceptor(jwa.ES256, cryptoprovider, sign, verify)
	new(types.SignerInterceptor).CreateInterceptor(jwa.ES384, cryptoprovider, sign, verify)
	new(types.SignerInterceptor).CreateInterceptor(jwa.ES512, cryptoprovider, sign, verify)
	new(types.SignerInterceptor).CreateInterceptor(jwa.EdDSA, cryptoprovider, sign, verify)
	new(types.SignerInterceptor).CreateInterceptor(jwa.SignatureAlgorithm(jwa.Ed25519), cryptoprovider, sign, verify)
}

func DisableCryptoProvider() {

	if verify {
		jws.UnregisterVerifier(jwa.PS256)
		jws.UnregisterVerifier(jwa.PS384)
		jws.UnregisterVerifier(jwa.PS512)
		jws.UnregisterVerifier(jwa.ES256)
		jws.UnregisterVerifier(jwa.ES384)
		jws.UnregisterVerifier(jwa.ES512)
		jws.UnregisterVerifier(jwa.EdDSA)
		jws.UnregisterVerifier(jwa.SignatureAlgorithm(jwa.Ed25519))
	}

	if sign {
		jws.UnregisterSigner(jwa.PS256)
		jws.UnregisterSigner(jwa.PS384)
		jws.UnregisterSigner(jwa.PS512)
		jws.UnregisterSigner(jwa.ES256)
		jws.UnregisterSigner(jwa.ES384)
		jws.UnregisterSigner(jwa.ES512)
		jws.UnregisterSigner(jwa.EdDSA)
		jws.UnregisterSigner(jwa.SignatureAlgorithm(jwa.Ed25519))
	}

	if sign && verify {
		jwa.UnregisterSignatureAlgorithm(jwa.PS256)
		jwa.UnregisterSignatureAlgorithm(jwa.PS384)
		jwa.UnregisterSignatureAlgorithm(jwa.PS512)
		jwa.UnregisterSignatureAlgorithm(jwa.ES256)
		jwa.UnregisterSignatureAlgorithm(jwa.ES384)
		jwa.UnregisterSignatureAlgorithm(jwa.ES512)
		jwa.UnregisterSignatureAlgorithm(jwa.EdDSA)
		jwa.UnregisterSignatureAlgorithm(jwa.SignatureAlgorithm(jwa.Ed25519))
	}

}

func ParseSelfSigned(tokenString string, options ...ljwt.ParseOption) (ljwt.Token, error) {

	if tokenString == "" {
		return nil, ljwt.ErrInvalidJWT()
	}

	selfSignedOption := ljwt.WithKeyProvider(jws.KeyProviderFunc(func(ctx context.Context,
		ks jws.KeySink,
		s *jws.Signature,
		m *jws.Message) error {

		alg := s.ProtectedHeaders().Algorithm()

		key := s.ProtectedHeaders().JWK()

		if key == nil {
			return ljwt.ErrInvalidJWT()
		}

		ks.Key(alg, key)
		return nil
	}))
	options = append(options, selfSignedOption)
	return ljwt.Parse([]byte(tokenString), options...)
}

func CombineJwksSets(sets []jwk.Set, context context.Context) jwk.Set {
	combinedSet := jwk.NewSet()
	for _, item := range sets {
		iterator := item.Keys(context)
		for i := 0; i < item.Len(); i++ {
			if iterator.Next(context) {
				key := iterator.Pair().Value.(jwk.Key)

				_, exist := combinedSet.LookupKeyID(key.KeyID())

				if exist {
					logrus.Error("Key " + key.KeyID() + " already exist or is twice available. Key was NOT ADDED to set")
				} else {
					err := combinedSet.AddKey(key)
					if err != nil {
						logrus.Error("Key " + key.KeyID() + " already exist or is twice available. Key was NOT ADDED to set")
					}
				}
			}
		}
	}
	return combinedSet
}

func ParseRequest(r *http.Request, options ...ljwt.ParseOption) (ljwt.Token, error) {
	var sets []jwk.Set
	for _, f := range fetchers {
		keys, err := f.GetKeys()
		if err == nil {
			sets = append(sets, keys)
		} else {
			logrus.Error(err)
		}
	}

	keySetOption := ljwt.WithKeySet(CombineJwksSets(sets, context.Background()))
	options = append(options, keySetOption)
	return ljwt.ParseRequest(r, options...)
}

func EncryptJweMessage(payload []byte, alg jwa.KeyAlgorithm, receipientKeys ...jwk.Key) *jwe.Message {
	options := []jwe.EncryptOption{jwe.WithJSON()}
	for _, key := range receipientKeys {
		var pubKey interface{}
		err := key.Raw(&pubKey)
		if err != nil {
			logrus.Error(err)
			return nil
		}
		options = append(options, jwe.WithKey(alg, pubKey))
	}
	encrypted, err := jwe.Encrypt([]byte(payload), options...)
	if err != nil {
		logrus.Errorf("failed to encrypt payload: %s\n", err)
		return nil
	}
	msg := jwe.NewMessage()
	msg.UnmarshalJSON(encrypted)
	return msg
}

func DecryptJweMessage(msg *jwe.Message, options ...jwe.DecryptOption) ([]byte, error) {
	if len(options) == 0 {
		return nil, errors.New("No Options for decryption set. Set at least WithKey or WithProvider")
	}

	payload, err := msg.MarshalJSON()

	if err != nil {
		logrus.Errorf("failed to marshal payload: %s\n", err)
		return nil, err
	}

	decrypted, err := jwe.Decrypt(payload, options...)
	if err != nil {
		logrus.Errorf("failed to decrypt payload: %s\n", err)
		return nil, err
	}
	return decrypted, nil
}
