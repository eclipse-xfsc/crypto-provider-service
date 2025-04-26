package signer

import (
	"context"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	ariesigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"golang.org/x/exp/slices"

	"gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/engine/core/types"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/golib/errors"
)

const (
	EdSignature = "ed25519signature2020"
)

func (s *Service) addCredentialProof(ctx context.Context, issuer string, namespace, group, keyname string, vc *verifiable.Credential, nonce *string, sigType string) (*verifiable.Credential, error) {
	key, err := s.getKey(ctx, namespace, group, keyname, sigType)

	if err != nil {
		return nil, &errors.Error{
			Kind:    errors.NotFound,
			Err:     err,
			Message: err.Error(),
		}
	}

	if !slices.Contains(s.supportedKeys, string(key.KeyType)) {
		return nil, &errors.Error{
			Kind:    errors.Unknown,
			Err:     err,
			Message: fmt.Sprintf("unsupported key type: %s", key.KeyType),
		}
	}

	proofContext, err := s.proofContext(ctx, issuer, namespace, group, key.Identifier.KeyId, nonce, sigType)
	if err != nil {
		return nil, &errors.Error{
			Kind:    errors.Internal,
			Err:     err,
			Message: err.Error(),
		}
	}

	if err := vc.AddLinkedDataProof(proofContext, jsonld.WithDocumentLoader(s.docLoader)); err != nil {
		return nil, &errors.Error{
			Kind:    errors.Internal,
			Err:     err,
			Message: err.Error(),
		}
	}

	return vc, nil
}

func (s *Service) addPresentationProof(ctx context.Context, issuer, keyNamespace, group, keyName string, vp *verifiable.Presentation, nonce *string, sigType string) (*verifiable.Presentation, error) {
	key, err := s.getKey(ctx, keyNamespace, group, keyName, sigType)

	if err != nil {
		return nil, &errors.Error{
			Kind:    errors.NotFound,
			Err:     err,
			Message: err.Error(),
		}
	}

	if !slices.Contains(s.supportedKeys, string(key.KeyType)) {
		return nil, &errors.Error{
			Kind:    errors.Unknown,
			Err:     err,
			Message: fmt.Sprintf("unsupported key type: %s", key.KeyType),
		}
	}

	if vp.Holder == "" {
		vp.Holder = issuer //term "issuer" is a bit stupid, its actually the holder
	}

	proofContext, err := s.proofContext(ctx, issuer, keyNamespace, group, key.Identifier.KeyId, nonce, sigType)
	if err != nil {
		return nil, &errors.Error{
			Kind:    errors.Internal,
			Err:     err,
			Message: err.Error(),
		}
	}

	if err := vp.AddLinkedDataProof(proofContext, jsonld.WithDocumentLoader(s.docLoader)); err != nil {
		return nil, &errors.Error{
			Kind:    errors.Internal,
			Err:     err,
			Message: err.Error(),
		}
	}

	return vp, nil
}

func (s *Service) getKey(ctx context.Context, namespace, group, keyname, sigType string) (*types.CryptoKey, error) {

	identifier := types.CryptoIdentifier{
		KeyId: keyname,
		CryptoContext: types.CryptoContext{
			Namespace: namespace,
			Group:     group,
			Context:   ctx,
		},
	}

	key, err := s.cryptoProvider.GetKey(identifier)
	if err != nil || key == nil {
		return nil, errors.New(fmt.Sprintf("failed to fetch key with id %s", identifier.KeyId), err)
	}

	if key.KeyType != types.Ed25519 && sigType == EdSignature {
		return nil, &errors.Error{
			Kind:    errors.Internal,
			Message: "Key doesnt match to signature type. Must be ed key.",
		}
	}

	if err != nil {
		return nil, errors.New("error getting signing key", err)
	}

	return key, nil
}

// proofContext is used to create proofs.
func (s *Service) proofContext(ctx context.Context, issuer, namespace, group, key string, nonce *string, signature string) (*verifiable.LinkedDataProofContext, error) {
	sigSuite, sigType, err := s.signatureSuite(ctx, namespace, group, key, signature)
	if err != nil {
		return nil, err
	}

	method := issuer + "#" + key
	if strings.HasPrefix(issuer, "did:jwk") {
		method = issuer + "#0"
	}

	proofContext := &verifiable.LinkedDataProofContext{
		Suite:              sigSuite,
		SignatureType:      sigType,
		VerificationMethod: method,
	}

	if signature == EdSignature {
		proofContext.SignatureRepresentation = verifiable.SignatureProofValue
	} else {
		proofContext.SignatureRepresentation = verifiable.SignatureJWS
	}

	if nonce != nil {
		proofContext.Challenge = *nonce
	}

	return proofContext, nil
}

// signatureSuite is used to create digital signatures on proofs.
func (s *Service) signatureSuite(ctx context.Context, namespace, group, key, signature string) (sigSuite ariesigner.SignatureSuite, sigType string, err error) {
	wrapper := Wrapper{
		CryptoProvider: s.cryptoProvider,
		Namespace:      namespace,
		Group:          group,
		Key:            key,
		Context:        ctx,
	}

	err = wrapper.Init()

	if err != nil {
		return nil, "", err
	}

	if signature == EdSignature {
		sigType = "Ed25519Signature2020"
		sigSuite = ed25519signature2020.New(suite.WithSigner(&wrapper))
	} else {
		sigType = "JsonWebSignature2020"
		sigSuite = jsonwebsignature2020.New(suite.WithSigner(&wrapper))
	}
	return sigSuite, sigType, nil
}
