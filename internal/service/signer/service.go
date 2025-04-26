package signer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/web"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/piprate/json-gold/ld"

	"go.uber.org/zap"

	"github.com/eclipse-xfsc/crypto-provider-service/gen/signer"
	jwkvdr "github.com/eclipse-xfsc/crypto-provider-service/internal/service/signer/jwkvdr"
	policy "github.com/eclipse-xfsc/crypto-provider-service/internal/service/signer/policy"
	messaging "github.com/eclipse-xfsc/crypto-provider-service/pkg/messaging"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/engine/core/types"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/messaging/cloudeventprovider"
	commonMessaging "gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/libraries/messaging"
	"gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/libraries/messaging/common"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/golib/errors"
)

//go:generate counterfeiter . Vault

var defaultJSONLDContexts = []string{
	"https://www.w3.org/2018/credentials/v1",
	"https://schema.org",
}

type EngineInfo struct {
	Namespace string
	Group     string
	Engine    string
}

type Service struct {
	verifiers       []Verifier
	cryptoProvider  types.CryptoProvider
	supportedKeys   []string // supported key types
	docLoader       *ld.CachingDocumentLoader
	keyFetcher      verifiable.PublicKeyFetcher
	natsTopic       string
	natsHost        string
	natsStatusTopic string
	sdjwtServiceUrl string
	logger          *zap.Logger
	messageClient   *cloudeventprovider.CloudEventProviderClient
}

type Verifier interface {
	VerifyCredential(ctx context.Context, vc *verifiable.Credential) error
	VerifyPresentation(ctx context.Context, vp *verifiable.Presentation) error
}

type Wrapper struct {
	CryptoProvider types.CryptoProvider
	Namespace      string
	Group          string
	Key            string
	Context        context.Context
	Type           types.KeyType
	Identifier     types.CryptoIdentifier
}

func (s *Wrapper) Init() error {
	s.Identifier = types.CryptoIdentifier{
		KeyId: s.Key,
		CryptoContext: types.CryptoContext{
			Namespace: s.Namespace,
			Group:     s.Group,
			Context:   s.Context,
		},
	}
	key, err := s.CryptoProvider.GetKey(s.Identifier)

	if err != nil {
		return err
	}
	s.Type = key.KeyType
	return nil
}

func (s *Wrapper) Sign(data []byte) ([]byte, error) {
	return s.CryptoProvider.Sign(s.Identifier, data)
}

func (s *Wrapper) Alg() string {
	return getSignatureType(s.Type)
}

func getSignatureType(s types.KeyType) string {
	switch s {
	case types.Ed25519:
		return "EdDSA"
	case types.Ecdsap256:
		return "ES256"
	case types.Ecdsap384:
		return "ES384"
	case types.Ecdsap521:
		return "ES512"
	case types.Rsa2048:
		return "PS256"
	case types.Rsa3072:
		return "PS256"
	case types.Rsa4096:
		return "PS256"
	}
	return "Undefined"
}

func New(cryptoProvider types.CryptoProvider, verifiers []Verifier, supportedKeys []string, docLoader *ld.CachingDocumentLoader, logger *zap.Logger, natsHost string, natsTopic string, natsStatusTopic string, wg *sync.WaitGroup, sdjwtServiceUrl string) *Service {
	// only DID:WEB and DID:KEY methods are supported currently
	webVDR := web.New()
	keyVDR := key.New()
	jwkVDR := jwkvdr.New()

	registry := vdr.New(
		vdr.WithVDR(webVDR),
		vdr.WithVDR(keyVDR),
		vdr.WithVDR(jwkVDR),
	)
	keyResolver := verifiable.NewVDRKeyResolver(registry)

	svc := &Service{
		cryptoProvider:  cryptoProvider,
		verifiers:       verifiers,
		supportedKeys:   supportedKeys,
		docLoader:       docLoader,
		keyFetcher:      keyResolver.PublicKeyFetcher(),
		logger:          logger,
		natsTopic:       natsTopic,
		natsHost:        natsHost,
		natsStatusTopic: natsStatusTopic,
		sdjwtServiceUrl: sdjwtServiceUrl,
	}

	wg.Add(1)

	go svc.StartMessaging(wg)

	return svc
}

func (s *Service) GenerateJwk(ctx context.Context, key, namespace, group string) (jwk.Key, string, error) {
	identifier := types.CryptoIdentifier{
		KeyId: key,
		CryptoContext: types.CryptoContext{
			Namespace: namespace,
			Group:     group,
			Context:   ctx,
		},
	}

	k, err := s.cryptoProvider.GetKey(identifier)
	if err != nil {
		s.logger.Error("error getting verification method", zap.Error(err))
		return nil, "", err
	}

	pubKey, err := k.GetJwk()

	if err != nil {
		s.logger.Error("error making JWK from Provider key",
			zap.String("keyType", string(k.KeyType)),
			zap.Error(err),
		)
		return nil, "", fmt.Errorf("error converting vault key to JWK")
	}

	b, err := json.Marshal(pubKey)

	if err != nil {
		s.logger.Error("error marshalling jwk",
			zap.String("key", pubKey.KeyID()),
			zap.Error(err),
		)
		return nil, "", fmt.Errorf("error converting vault key to JWK")
	}

	return pubKey, "did:jwk:" + base64.RawURLEncoding.EncodeToString(b), nil

}

// Namespaces returns all keys namespaces, which corresponds to enabled Vault
// transit engines.
func (s *Service) Namespaces(ctx context.Context) ([]string, error) {
	logger := s.logger.With(zap.String("operation", "namespaces"))

	cctx := types.CryptoContext{
		Context: ctx,
		Engine:  "transit",
	}
	namespaces, err := s.cryptoProvider.GetNamespaces(cctx)
	if err != nil {
		logger.Error("error getting keys namespaces", zap.Error(err))
		return nil, errors.New("error getting keys namespaces", err)
	}

	return namespaces, nil
}

// NamespaceKeys returns all keys names for a given namespace.
func (s *Service) NamespaceKeys(ctx context.Context, req *signer.NamespaceKeysRequest) ([]string, error) {
	logger := s.logger.With(
		zap.String("operation", "namespaceKeys"),
		zap.String("namespace", req.Namespace),
		zap.String("group", req.XGroup),
	)

	filter := types.CryptoFilter{
		CryptoContext: types.CryptoContext{
			Namespace: req.Namespace,
			Context:   ctx,
			Group:     req.XGroup,
			Engine:    "transit",
		},
	}
	keys, err := s.cryptoProvider.GetKeys(filter)
	if err != nil {
		if errors.Is(errors.NotFound, err) {
			logger.Error("no namespace keys found", zap.Error(err))
			return nil, errors.New("no keys found in namespace", err)
		}

		logger.Error("error getting namespace keys", zap.Error(err))
		return nil, errors.New("error getting namespace keys", err)
	}

	keyNames := make([]string, 0)

	for _, val := range keys.Keys {
		keyNames = append(keyNames, val.Identifier.KeyId)
	}

	return keyNames, nil
}

// VerificationMethod returns a single public key formatted as DID verification method.
func (s *Service) VerificationMethod(ctx context.Context, req *signer.VerificationMethodRequest) (*signer.DIDVerificationMethod, error) {
	logger := s.logger.With(
		zap.String("operation", "verificationMethod"),
		zap.String("namespace", req.Namespace),
		zap.String("key", req.Key),
		zap.String("did", req.Did),
		zap.String("group", req.Group),
	)

	pubKey, did, err := s.GenerateJwk(ctx, req.Key, req.Namespace, req.Group)

	if err != nil {
		logger.Error("error generating jwk",
			zap.String("key", req.Key),
			zap.Error(err),
		)
		return nil, fmt.Errorf("error generating did:jwk")
	}

	id := req.Did
	controller := req.Did

	if strings.HasPrefix(req.Did, "did:jwk") {
		controller = did
		id = id + "#0"
	} else {
		id = id + "#" + req.Key
	}

	return &signer.DIDVerificationMethod{
		ID:           id,
		Type:         "JsonWebKey2020",
		Controller:   controller,
		PublicKeyJwk: pubKey,
	}, nil
}

func (s *Service) getVerficationMethods(ctx context.Context, namespace string, group string, engine string, did string) (res []*signer.DIDVerificationMethod, err error) {
	logger := s.logger.With(
		zap.String("operation", "verificationMethods"),
		zap.String("namespace", namespace),
		zap.String("did", did),
		zap.String("group", group),
	)

	filter := types.CryptoFilter{
		CryptoContext: types.CryptoContext{
			Namespace: namespace,
			Group:     group,
			Context:   ctx,
			Engine:    engine,
		},
	}
	res = make([]*signer.DIDVerificationMethod, 0)
	keys, err := s.cryptoProvider.GetKeys(filter)
	if err != nil {
		if !errors.Is(errors.NotFound, err) {
			err = &errors.Error{Message: "error getting keys", Err: err, Kind: errors.Internal}
			logger.Error("error getting keys from vault", zap.Error(err))
			return nil, err
		}
		logger.Warn("no keys in vault")
	}

	for _, key := range keys.Keys {

		pubKey, err := key.GetJwk()
		if err != nil {
			logger.Error("error making JWK from Vault key",
				zap.String("key", key.Identifier.KeyId),
				zap.String("keyType", string(key.KeyType)),
				zap.Error(err),
			)
			return nil, fmt.Errorf("error converting vault key to JWK")
		}

		vm := &signer.DIDVerificationMethod{
			ID:           did + "#" + key.Identifier.KeyId,
			Type:         "JsonWebKey2020",
			Controller:   did,
			PublicKeyJwk: pubKey,
		}

		res = append(res, vm)
	}

	return res, nil
}

// VerificationMethods returns all public keys from Vault or OCM.
func (s *Service) VerificationMethods(ctx context.Context, req *signer.VerificationMethodsRequest) (res []*signer.DIDVerificationMethod, err error) {
	return s.getVerficationMethods(ctx, req.Namespace, req.Group, req.Engine, req.Did)
}

// JwkPublicKey returns public key by name and namespace.
func (s *Service) JwkPublicKey(ctx context.Context, req *signer.JwkPublicKeyRequest) (any, error) {
	logger := s.logger.With(
		zap.String("operation", "jwkPublicKey"),
		zap.String("namespace", req.Namespace),
		zap.String("group", req.Group),
		zap.String("key", req.Key),
		zap.String("engine", req.Engine),
	)

	identifier := types.CryptoIdentifier{
		KeyId: req.Key,
		CryptoContext: types.CryptoContext{
			Namespace: req.Namespace,
			Group:     req.Group,
			Context:   ctx,
			Engine:    req.Engine,
		},
	}

	key, err := s.cryptoProvider.GetKey(identifier)
	if err != nil {
		logger.Error("error getting key", zap.Error(err))
		err = &errors.Error{
			Err:  err,
			Kind: errors.NotFound,
		}
		return nil, err
	}

	pubKey, err := key.GetJwk()
	if err != nil {
		logger.Error("error converting public key to jwk",
			zap.String("key", key.Identifier.KeyId),
			zap.String("keyType", string(key.KeyType)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("error converting public key to jwk: %v", err)
	}

	return pubKey, nil
}

func (s *Service) addProof(ctx context.Context, credential any, format string, namespace string, group string, key string, nonce *string, logger *zap.Logger, sigType string, disclosureFrame []string) (interface{}, error) {
	vcBytes, err := json.Marshal(credential)
	if err != nil {
		logger.Error("credential is not valid json", zap.Error(err))
		return nil, errors.New(errors.BadRequest, err.Error())
	}

	// credential may not have a proof, so disable proofCheck on first round
	vc, err := s.parseCredential(vcBytes, false)
	if err != nil {
		logger.Error("error parsing verifiable credential", zap.Error(err))
		if strings.Contains(err.Error(), "JSON-LD doc has different structure after compaction") {
			return nil, errors.New(errors.BadRequest, "JSON-LD doc has different structure after compaction: some attributes may not be described by schema")
		}
		return nil, errors.New(errors.BadRequest, err.Error())
	}

	if format == "vc+sd-jwt" {
		return s.createSdJwt(vc, namespace, group, key, sigType, disclosureFrame, "", nil, nil)
	}

	if format == "ldp_vc" {
		// if the given credential has at least one proof, check again to verify the proofs
		if len(vc.Proofs) > 0 {
			vc, err = s.parseCredential(vcBytes, true)
			if err != nil {
				logger.Error("credential proofs cannot be verified", zap.Error(err))
				return nil, errors.New(errors.Forbidden, err.Error())
			}
		}

		if err := validateCredentialSubject(vc.Subject); err != nil {
			logger.Error(err.Error())
			return nil, errors.New(errors.BadRequest, err.Error())
		}

		vcWithProof, err := s.addCredentialProof(ctx, vc.Issuer.ID, namespace, group, key, vc, nonce, sigType)
		if err != nil {
			logger.Error("error making credential proof", zap.Error(err))
			return nil, errors.New(err)
		}

		return vcWithProof, nil
	}
	return nil, &errors.Error{
		Kind:    errors.BadRequest,
		Message: "Unknown format.",
	}
}

// CredentialProof adds a proof to a given Verifiable Credential.
func (s *Service) CredentialProof(ctx context.Context, req *signer.CredentialProofRequest) (interface{}, error) {
	logger := s.logger.With(
		zap.String("operation", "credentialProof"),
		zap.String("namespace", req.Namespace),
		zap.String("key", req.Key),
		zap.String("group", req.Group),
	)
	return s.addProof(ctx, req.Credential, req.Format, req.Namespace, req.Group, req.Key, req.Nonce, logger, req.SignatureType, req.DisclosureFrame)
}

func (s *Service) convertIssuer(ctx context.Context, key, namespace, group string, iss *string) (string, error) {
	var issuer string
	if iss == nil {
		_, did, err := s.GenerateJwk(ctx, key, namespace, group)
		if err != nil {
			s.logger.Error("error generating jwk", zap.Error(err))
			return "", errors.New(errors.BadRequest, err.Error())
		}
		s.logger.Debug("DID Generated:", zap.String("DID:", did))
		issuer = did
	} else {
		issuer = *iss
	}
	return issuer, nil
}

// PresentationProof adds a proof to a given Verifiable Presentation.
func (s *Service) PresentationProof(ctx context.Context, req *signer.PresentationProofRequest) (interface{}, error) {

	logger := s.logger.With(
		zap.String("operation", "presentationProof"),
		zap.String("namespace", req.Namespace),
		zap.String("group", req.Group),
		zap.String("key", req.Key),
	)

	if req.Format == "vc+sd-jwt" {

		if req.Presentation == nil {
			return nil, errors.New("sdjwt presentation is nil")
		}

		p, ok := req.Presentation.(string)

		if !ok {
			return nil, errors.New("sdjwt presentation in wrong format")
		}

		holderKey, err := s.cryptoProvider.GetKey(types.CryptoIdentifier{
			KeyId: req.Key,
			CryptoContext: types.CryptoContext{
				Namespace: req.Namespace,
				Group:     req.Group,
				Context:   ctx,
				Engine:    "transit",
			},
		})

		if err != nil {
			return nil, errors.New("holder key not available")
		}

		var kid string

		if req.Issuer != nil {
			kid = *req.Issuer
		}

		return s.createSdJwtPresentation(p, kid, req.Namespace, req.Group, req.Key, getSignatureType(holderKey.KeyType), *req.Aud, *req.Nonce, req.DisclosureFrame)
	}

	if req.Format == "ldp_vc" {

		vpBytes, err := json.Marshal(req.Presentation)
		if err != nil {
			logger.Error("presentation is not valid json", zap.Error(err))
			return nil, errors.New(errors.BadRequest, err.Error())
		}

		issuer, err := s.convertIssuer(ctx, req.Key, req.Namespace, req.Group, req.Issuer)

		if err != nil {
			logger.Error("issuer conversion error", zap.Error(err))
			return nil, errors.New(errors.BadRequest, err.Error())
		}

		vp, err := verifiable.ParsePresentation(
			vpBytes,
			verifiable.WithPresJSONLDDocumentLoader(s.docLoader),
			verifiable.WithPresStrictValidation(),
		)
		if err != nil {
			logger.Error("error parsing verifiable presentation", zap.Error(err))
			if strings.Contains(err.Error(), "JSON-LD doc has different structure after compaction") {
				return nil, errors.New(errors.BadRequest, "JSON-LD doc has different structure after compaction: some attributes may not be described by schema")
			}
			return nil, errors.New(errors.BadRequest, err.Error())
		}

		if len(vp.Credentials()) == 0 {
			logger.Error("presentation must contain at least 1 verifiable credential")
			return nil, errors.New(errors.BadRequest, "presentation must contain at least 1 verifiable credential")
		}

		for _, cred := range vp.Credentials() {
			cred, ok := cred.(map[string]interface{})
			if !ok {
				logger.Error("presentation has credentials in unsupported format")
				return nil, errors.New(errors.BadRequest, "presentation has credentials in unsupported format")
			}

			credJSON, err := json.Marshal(cred)
			if err != nil {
				logger.Error("fail to encode credential to json", zap.Error(err))
				return nil, errors.New("fail to encode credential to json", err)
			}

			_, err = s.parseCredential(credJSON, true)
			if err != nil {
				logger.Error("error validating credential", zap.Error(err))
				if strings.Contains(err.Error(), "JSON-LD doc has different structure after compaction") {
					return nil, errors.New(errors.BadRequest, "JSON-LD doc has different structure after compaction: some attributes may not be described by schema")
				}
				return nil, errors.New(errors.BadRequest, "error validating credential", err)
			}

			if err := validateCredentialSubject(cred["credentialSubject"]); err != nil {
				logger.Error(err.Error())
				return nil, errors.New(errors.BadRequest, err.Error())
			}
		}

		vpWithProof, err := s.addPresentationProof(ctx, issuer, req.Namespace, req.Group, req.Key, vp, req.Nonce, req.SignatureType)
		if err != nil {
			logger.Error("error making presentation proof", zap.Error(err))
			return nil, errors.New(err)
		}

		return vpWithProof, nil
	}
	return nil, errors.New("unsupported format")
}

func (s *Service) getStatusListEntry(namespace, group, origin string) (string, string, string, int, error) {
	if s.natsStatusTopic != "" {

		client, _ := cloudeventprovider.New(
			cloudeventprovider.Config{Protocol: cloudeventprovider.ProtocolTypeNats, Settings: cloudeventprovider.NatsConfig{
				Url:          s.natsHost,
				TimeoutInSec: time.Minute,
			}},
			cloudeventprovider.ConnectionTypeReq,
			s.natsStatusTopic,
		)

		var req = commonMessaging.CreateStatusListEntryRequest{
			Request: common.Request{
				TenantId:  namespace,
				RequestId: uuid.NewString(),
				GroupId:   group,
			},
			Origin: origin,
		}

		b, _ := json.Marshal(req)

		testEvent, _ := cloudeventprovider.NewEvent("signer-service", "create", b)

		ev, _ := client.RequestCtx(context.Background(), testEvent)

		var rep commonMessaging.CreateStatusListEntryReply

		err := json.Unmarshal(ev.Data(), &rep)

		if err != nil {
			return "", "", "", -1, err
		}

		if rep.Error != nil {
			return "", "", "", -1, errors.New("error on status list creation")
		}

		return rep.StatusUrl, rep.Type, rep.Purpose, rep.Index, err
	}
	return "", "", "", -1, errors.New("unknown operation")
}

func (s *Service) appendVCStatus(vc *verifiable.Credential, namespace string, group string, origin string) error {

	url, typ, purpose, index, err := s.getStatusListEntry(namespace, group, origin)

	if err != nil {
		return err
	}

	vc.Status = &verifiable.TypedID{
		ID:   url + "#" + uuid.NewString(),
		Type: typ,
		CustomFields: verifiable.CustomFields{
			"statusPurpose":        purpose,
			"statusListCredential": url,
			"statusListIndex":      index,
		},
	}

	return err
}

func (s *Service) appendTermsOfUse(vc *verifiable.Credential, namespace string, group string) error {

	input := make(map[string]interface{})
	input["tenant"] = namespace
	input["group"] = group
	result, err := policy.GetPolicyResult(input, "TERMSOFUSE_POLICY")
	if result == nil && err == nil {
		return nil
	}

	if err != nil {
		return err
	}

	var terms []verifiable.TypedID

	b, err := json.Marshal(result["result"])

	json.Unmarshal(b, &terms)

	vc.TermsOfUse = append(vc.TermsOfUse, terms...)

	return err
}

func (s *Service) appendEvidence(vc *verifiable.Credential, namespace string, group string) error {

	input := make(map[string]interface{})
	input["tenant"] = namespace
	input["group"] = group
	result, err := policy.GetPolicyResult(input, "EVIDENCE_POLICY")
	if result == nil && err == nil {
		return nil
	}

	if err != nil {
		return err
	}

	var evidence verifiable.Evidence

	b, err := json.Marshal(result["result"])

	json.Unmarshal(b, &evidence)

	vc.Evidence = evidence

	return err
}

// CreateCredential creates Verifiable Credential with proof from raw JSON data.
func (s *Service) CreateCredential(ctx context.Context, req *signer.CreateCredentialRequest) (interface{}, error) {
	logger := s.logger.With(
		zap.String("operation", "createCredential"),
		zap.String("namespace", req.Namespace),
		zap.String("group", req.Group),
		zap.String("key", req.Key),
	)
	logger.Debug("Start Testing Credential Subject")
	if req.CredentialSubject == nil {
		logger.Error("invalid or missing credential subject")
		return nil, &errors.Error{
			Kind:    errors.BadRequest,
			Message: "invalid or missing credential subject",
		}
	}

	credSubject, ok := req.CredentialSubject.(map[string]interface{})
	if !ok || len(credSubject) == 0 {
		logger.Error("invalid credential subject: non-empty map is expected")
		return nil, &errors.Error{
			Kind:    errors.BadRequest,
			Message: "invalid credential subject: non-empty map is expected",
		}
	}
	logger.Debug("Start Testing Context")
	// add additional jsonld contexts only if they are different from the default

	jsonldContexts := defaultJSONLDContexts
	for _, jsonldContext := range req.Context {
		if !containContext(defaultJSONLDContexts, jsonldContext) {
			jsonldContexts = append(jsonldContexts, jsonldContext)
		}
	}

	if req.SignatureType == EdSignature {
		jsonldContexts = append(jsonldContexts, "https://w3id.org/security/suites/ed25519-2020/v1")
	} else {
		jsonldContexts = append(jsonldContexts, "https://w3id.org/security/suites/jws-2020/v1")
	}

	logger.Debug("Start Testing Custom Stuff")
	var subject verifiable.Subject
	var holderJwk any
	if subjectID, ok := credSubject["id"].(string); ok && len(subjectID) > 0 {
		subject.ID = subjectID
		delete(credSubject, "id")
	} else {
		if req.Holder != nil {

			parts := strings.Split(*req.Holder, ".")

			if len(parts) == 3 { //check for jwt token
				header, _ := base64.RawURLEncoding.DecodeString(parts[0])

				if header != nil {
					var h map[string]interface{}
					json.Unmarshal(header, &h)
					holderJwk = h["jwk"]
				} else {
					return nil, errors.New("no valid jwk header in holder token")
				}
				b, _ := json.Marshal(holderJwk)
				subject.ID = "did:jwk:" + base64.RawURLEncoding.EncodeToString(b)

			} else {
				//TODO Here could be resolver for other JWKs
				subject.ID = *req.Holder
			}
		}
	}

	subject.CustomFields = credSubject

	vc := &verifiable.Credential{
		Context: jsonldContexts,
		Types:   []string{verifiable.VCType},
		Issued:  &util.TimeWrapper{Time: time.Now()},
		Subject: subject,
	}

	if req.Type != nil {
		vc.Types = req.Type
	}

	cryptoIdentifier := types.CryptoIdentifier{
		KeyId: req.Key,
		CryptoContext: types.CryptoContext{
			Namespace: req.Namespace,
			Group:     req.Group,
			Context:   ctx,
		},
	}

	logger.Debug("Start Creating JWK for issuer")

	if s.cryptoProvider == nil {
		return nil, &errors.Error{
			Kind:    errors.Internal,
			Message: "Crypto Engine not found",
		}
	}

	key, err := s.cryptoProvider.GetKey(cryptoIdentifier)

	if err != nil {
		return nil, &errors.Error{
			Kind:    errors.Internal,
			Message: "Error getting key from Crypto Engine.",
		}
	}

	if key.KeyType != types.Ed25519 && req.SignatureType == EdSignature {
		return nil, &errors.Error{
			Kind:    errors.Internal,
			Message: "Key doesnt match to signature type. Must be ed key.",
		}
	}

	jwk, err := key.GetJwk()

	if err != nil {
		return nil, &errors.Error{
			Kind:    errors.Internal,
			Message: "Error transforming jwk.",
		}
	}
	logger.Debug("Start Marshalling Key")
	bytes, err := json.Marshal(jwk)
	if err != nil {
		logger.Error("error getting keys.", zap.Error(err))
		return nil, &errors.Error{
			Kind:    errors.Internal,
			Message: "Error getting keys.",
		}
	}

	logger.Debug("Start Build issuer")
	if req.Issuer != nil {
		vc.Issuer = verifiable.Issuer{ID: *req.Issuer}
	} else {
		vc.Issuer = verifiable.Issuer{ID: "did:jwk:" + base64.RawURLEncoding.EncodeToString(bytes)}
	}

	if req.Status != nil && *req.Status {
		logger.Debug("Append Status")
		err = s.appendVCStatus(vc, req.Namespace, req.Group, req.XOrigin)
	}

	if err != nil {
		return nil, &errors.Error{
			Kind:    errors.Internal,
			Message: "error during revocation appending.",
		}
	}

	logger.Debug("Append Terms of Use")
	err = s.appendTermsOfUse(vc, req.Namespace, req.Group)

	if err != nil {
		return nil, &errors.Error{
			Kind:    errors.Internal,
			Message: "error during terms of use appending.",
		}
	}

	logger.Debug("Append Evidence")
	err = s.appendEvidence(vc, req.Namespace, req.Group)

	if err != nil {
		return nil, &errors.Error{
			Kind:    errors.Internal,
			Message: "error during terms of use appending.",
		}
	}

	if req.Format == "vc+sd-jwt" {
		logger.Debug("Start Building sd jwt vc...")

		return s.createSdJwt(vc, req.Namespace, req.Group, req.Key, getSignatureType(key.KeyType), req.DisclosureFrame, req.XOrigin, req.Status, holderJwk)
	}

	if req.Format == "ldp_vc" {

		logger.Debug("Validate Subject")
		err = validateCredentialSubject(vc.Subject)
		if err != nil {
			logger.Error("invalid credential subject", zap.Error(err))
			return nil, &errors.Error{
				Kind:    errors.BadRequest,
				Message: "invalid credential subject",
			}
		}

		logger.Debug("Start building ldp vc...")
		vcWithProof, err := s.addCredentialProof(ctx, vc.Issuer.ID, req.Namespace, req.Group, req.Key, vc, req.Nonce, req.SignatureType)
		if err != nil {
			logger.Error("error making credential proof", zap.Error(err))
			return nil, &errors.Error{
				Kind:    errors.Internal,
				Message: "error during signing",
			}
		}

		return vcWithProof, nil
	}

	return nil, &errors.Error{
		Kind:    errors.BadRequest,
		Message: "Unknown format.",
	}
}

// CreatePresentation creates VP with proof from raw JSON data.
func (s *Service) CreatePresentation(ctx context.Context, req *signer.CreatePresentationRequest) (interface{}, error) {

	logger := s.logger.With(
		zap.String("operation", "createPresentation"),
		zap.String("namespace", req.Namespace),
		zap.String("key", req.Key),
		zap.String("group", req.Group),
	)

	issuer, err := s.convertIssuer(ctx, req.Key, req.Namespace, req.Group, req.Issuer)

	if err != nil {
		logger.Error("issuer conversion error", zap.Error(err))
		return nil, errors.New(errors.BadRequest, err.Error())
	}

	if req.Data == nil || len(req.Data) == 0 {
		logger.Error("invalid or missing credentials data")
		return nil, errors.New(errors.BadRequest, "invalid or missing credentials data")
	}

	// prepare credentials to be included in the VP
	var credentials []*verifiable.Credential
	for _, credData := range req.Data {
		credSubject, ok := credData.(map[string]interface{})
		if !ok {
			logger.Error("invalid credential data: map is expected")
			return nil, errors.New(errors.BadRequest, "invalid credential data: map is expected")
		}

		vc := &verifiable.Credential{
			Context: defaultJSONLDContexts,
			Types:   []string{verifiable.VCType},
			Issuer:  verifiable.Issuer{ID: issuer},
			Issued:  &util.TimeWrapper{Time: time.Now()},
			Subject: verifiable.Subject{
				CustomFields: credSubject,
			},
		}

		if err := validateCredentialSubject(vc.Subject); err != nil {
			logger.Error(err.Error())
			return nil, errors.New(errors.BadRequest, err.Error())
		}

		credentials = append(credentials, vc)
	}

	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(credentials...))
	if err != nil {
		logger.Error("error making verifiable presentation", zap.Error(err))
		return nil, err
	}

	// add additional jsonld contexts only if they are different from the default
	jsonldContexts := defaultJSONLDContexts
	for _, jsonldContext := range req.Context {
		if !containContext(defaultJSONLDContexts, jsonldContext) {
			jsonldContexts = append(jsonldContexts, jsonldContext)
		}
	}

	vp.Context = jsonldContexts
	vp.ID = issuer
	vp.Type = []string{verifiable.VPType}

	vpWithProof, err := s.addPresentationProof(ctx, issuer, req.Namespace, req.Group, req.Key, vp, req.Nonce, req.SignatureType)
	if err != nil {
		logger.Error("error making presentation proof", zap.Error(err))
		return nil, err
	}

	return vpWithProof, nil
}

func (s *Service) statusListCheckup(namespace, group *string, typ, purpose, url string, index int) (bool, error) {
	client, err := cloudeventprovider.New(
		cloudeventprovider.Config{Protocol: cloudeventprovider.ProtocolTypeNats, Settings: cloudeventprovider.NatsConfig{
			Url:          s.natsHost,
			TimeoutInSec: time.Minute,
		}},
		cloudeventprovider.ConnectionTypeReq,
		s.natsStatusTopic,
	)

	if err != nil {
		return false, err
	}

	req := commonMessaging.VerifyStatusListEntryRequest{
		Request: common.Request{
			TenantId: *namespace,
		},
		Type:      typ,
		Purpose:   purpose,
		Index:     index,
		StatusUrl: url,
	}

	if group != nil {
		req.GroupId = ""
	}

	b, err := json.Marshal(req)

	if err != nil {
		return false, err
	}

	e, err := cloudeventprovider.NewEvent("signer-service", "verify", b)

	if err != nil {
		return false, err
	}

	rep, err := client.RequestCtx(context.Background(), e)

	if err != nil {
		return false, err
	}

	var verify commonMessaging.VerifyStatusListEntryReply

	err = json.Unmarshal(rep.Data(), &verify)
	if err != nil {
		return false, err
	}
	return !verify.Revocated, nil
}

func (s *Service) verifyLdProof(ctx context.Context, credential []byte, namespace, group *string, logger *zap.Logger) (bool, error) {
	vc, err := s.parseCredentialWithProof(credential)

	if err != nil {
		logger.Error("error verifying credential", zap.Error(err))
		if strings.Contains(err.Error(), "JSON-LD doc has different structure after compaction") {
			return false, errors.New(errors.BadRequest, "JSON-LD doc has different structure after compaction: some attributes may not be described by schema")
		}
		return false, errors.New(errors.BadRequest, err.Error())
	}

	if err := validateCredentialSubject(vc.Subject); err != nil {
		logger.Error(err.Error())
		return false, errors.New(errors.BadRequest, err.Error())
	}

	// verify credential with all additional verifiers
	for _, v := range s.verifiers {
		if err := v.VerifyCredential(ctx, vc); err != nil {
			logger.Error("error verifying credential", zap.Error(err))
			return false, errors.New(errors.BadRequest, err.Error())
		}
	}

	arr, ok := vc.Subject.([]verifiable.Subject)

	if ok {
		for _, subject := range arr {
			pproof, ok := subject.CustomFields["provenanceProof"]
			byte, err := json.Marshal(pproof)
			if err != nil {
				return false, nil
			}
			if ok {
				return s.verifyLdProof(ctx, byte, namespace, group, logger)
			}
		}
	}

	if vc.Status != nil && namespace != nil {
		return s.statusListCheckup(namespace, group, vc.Status.Type,
			vc.Status.CustomFields["statusPurpose"].(string),
			vc.Status.CustomFields["statusListCredential"].(string),
			int(vc.Status.CustomFields["statusListIndex"].(float64)))
	}

	return true, nil
}

// VerifyCredential verifies the proof of a Verifiable Credential.
func (s *Service) VerifyCredential(ctx context.Context, req *signer.VerifyCredentialRequest) (*signer.VerifyResult, error) {
	logger := s.logger.With(zap.String("operation", "verifyCredential"))

	if req.XFormat == "vc+sd-jwt" {
		if req.DisclosureFrame == nil {
			return &signer.VerifyResult{Valid: false}, errors.New("no disclosure frame given")
		}
		return s.verifySdJwt(req.Credential, req.DisclosureFrame, false, "", "")
	}

	if req.XFormat == "ldp_vc" {
		// verify credential

		b, err := s.verifyLdProof(ctx, req.Credential, req.XNamespace, req.XGroup, logger)

		return &signer.VerifyResult{Valid: b}, err
	}

	return nil, errors.New(errors.BadRequest)
}

// VerifyPresentation verifies the proof of a Verifiable Presentation.
func (s *Service) VerifyPresentation(ctx context.Context, req *signer.VerifyPresentationRequest) (*signer.VerifyResult, error) {
	logger := s.logger.With(zap.String("operation", "verifyPresentation"))

	if req.XFormat == "vc+sd-jwt" {
		sdjwt := strings.Replace(strings.Replace(string(req.Presentation), `"`, "", -1), "\n", "", -1)
		return s.verifySdJwt([]byte(sdjwt), req.DisclosureFrame, true, *req.Nonce, *req.Aud)
	}

	// verify presentation
	vp, err := verifiable.ParsePresentation(
		req.Presentation,
		verifiable.WithPresPublicKeyFetcher(s.keyFetcher),
		verifiable.WithPresEmbeddedSignatureSuites(
			jsonwebsignature2020.New(suite.WithVerifier(jsonwebsignature2020.NewPublicKeyVerifier())),
			ed25519signature2020.New(suite.WithVerifier(ed25519signature2020.NewPublicKeyVerifier())),
		),
		verifiable.WithPresJSONLDDocumentLoader(s.docLoader),
		verifiable.WithPresStrictValidation(),
	)

	if err != nil {
		logger.Error("error verifying presentation", zap.Error(err))
		if strings.Contains(err.Error(), "JSON-LD doc has different structure after compaction") {
			return nil, errors.New(errors.BadRequest, "JSON-LD doc has different structure after compaction: some attributes may not be described by schema")
		}
		return nil, errors.New(errors.BadRequest, err.Error())
	}

	// check if the credential contains proof section
	if len(vp.Proofs) == 0 {
		logger.Error("verifiable presentation must have proof section")
		return nil, errors.New(errors.BadRequest, "verifiable presentation must have proof section")
	}

	if req.Aud != nil {
		_, ok := vp.CustomFields["aud"]
		if ok && vp.CustomFields["aud"] != req.Aud {
			return &signer.VerifyResult{Valid: false}, errors.New("Audience not matching")
		}
	}

	if req.Nonce != nil {
		_, ok := vp.CustomFields["nonce"]
		if ok && vp.CustomFields["noce"] != req.Nonce {
			return &signer.VerifyResult{Valid: false}, errors.New("Nonce not matching")
		}
	}

	if len(vp.Credentials()) == 0 {
		logger.Error("presentation must contain at least 1 verifiable credential")
		return nil, errors.New(errors.BadRequest, "presentation must contain at least 1 verifiable credential")
	}

	for _, cred := range vp.Credentials() {
		cred, ok := cred.(map[string]interface{})
		if !ok {
			logger.Error("presentation has credentials in unsupported format")
			return nil, errors.New(errors.BadRequest, "presentation has credentials in unsupported format")
		}

		credJSON, err := json.Marshal(cred)
		if err != nil {
			logger.Error("fail to encode credential to json", zap.Error(err))
			return nil, errors.New("fail to encode credential to json", err)
		}

		_, err = s.parseCredential(credJSON, true)
		if err != nil {
			logger.Error("error validating credential", zap.Error(err))
			if strings.Contains(err.Error(), "JSON-LD doc has different structure after compaction") {
				return nil, errors.New(errors.BadRequest, "JSON-LD doc has different structure after compaction: some attributes may not be described by schema")
			}
			return nil, errors.New(errors.BadRequest, err.Error())
		}

		if err := validateCredentialSubject(cred["credentialSubject"]); err != nil {
			logger.Error(err.Error())
			return nil, errors.New(errors.BadRequest, err.Error())
		}
	}

	for _, v := range s.verifiers {
		if err := v.VerifyPresentation(ctx, vp); err != nil {
			logger.Error("error verifying presentation", zap.Error(err))
			return nil, errors.New(errors.BadRequest, err.Error())
		}
	}

	return &signer.VerifyResult{Valid: true}, nil
}

// Sign creates digital signature on base64 encoded binary data.
func (s *Service) Sign(ctx context.Context, req *signer.SignRequest) (res *signer.SignResult, err error) {
	logger := s.logger.With(
		zap.String("operation", "sign"),
		zap.String("namespace", req.Namespace),
		zap.String("group", req.Group),
		zap.String("key", req.Key),
	)

	identifier := types.CryptoIdentifier{
		CryptoContext: types.CryptoContext{
			Namespace: req.Namespace,
			Group:     req.Group,
			Context:   ctx,
		},
		KeyId: req.Key,
	}

	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		logger.Error("cannot base64 decode data", zap.Error(err))
		return nil, errors.New(errors.BadRequest, "cannot base64 decode data", err)
	}

	signature, err := s.cryptoProvider.Sign(identifier, data)
	if err != nil {
		logger.Error("error signing data", zap.Error(err))
		return nil, errors.New(err)
	}

	encodedSignature := base64.StdEncoding.EncodeToString(signature)

	return &signer.SignResult{Signature: encodedSignature}, nil
}

func (s *Service) createSdJwtPresentation(sdjwt, kid, namespace, group, keyId, sigType, aud, nonce string, presentationFrame []string) (*string, error) {
	p := make(map[string]bool)
	for _, s := range presentationFrame {
		p[s] = true
	}

	para := map[string]interface{}{
		"sdjwt":             strings.Replace(strings.Replace(sdjwt, `"`, "", -1), "\n", "", -1),
		"presentationFrame": p,
		"holder": map[string]interface{}{
			"signer": map[string]string{
				"alg":       sigType,
				"namespace": namespace,
				"group":     group,
				"key":       keyId,
				"kid":       kid,
			},
		},
		"nonce": nonce,
		"aud":   aud,
	}

	b, err := json.Marshal(para)

	if err != nil {
		return nil, err
	}

	res, err := http.Post(s.sdjwtServiceUrl+"/present", "application/json", bytes.NewBuffer(b))

	if err != nil {
		return nil, err
	}

	bodyBytes, err := io.ReadAll(res.Body)
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, errors.New(string(bodyBytes))
	}

	if err != nil {
		return nil, err
	}
	var result map[string]string

	err = json.Unmarshal(bodyBytes, &result)

	if err != nil {
		return nil, err
	}

	r, ok := result["sdjwt"]

	if !ok {
		return nil, errors.New("no result")
	}

	return &r, nil
}

func (s *Service) createSdJwt(vc *verifiable.Credential, namespace, group, keyId, sigType string, disclosureFrame []string, origin string, status *bool, holderJwk any) (*string, error) {

	para := make(map[string]interface{})

	vct, ok := vc.CustomFields["vct"]

	if !ok {
		sub, ok := vc.Subject.([]verifiable.Subject)

		if !ok {

			if len(vc.Types) > 0 {
				for _, t := range vc.Types {
					if t != "VerifiableCredential" {
						vct = t
					}
				}

				if vct == "" {
					return nil, errors.New("No vct given")
				}

			} else {
				return nil, errors.New("No vct given")
			}
		} else {
			vct, ok = sub[0].CustomFields["vct"]
			if !ok {
				return nil, errors.New("No vct given")
			}
		}
	}

	para["vct"] = vct
	para["issuer"] = make(map[string]interface{})
	issuer := para["issuer"].(map[string]interface{})
	issuer["signer"] = make(map[string]interface{})
	signer := issuer["signer"].(map[string]interface{})
	signer["namespace"] = namespace
	signer["group"] = group
	signer["key"] = keyId

	if strings.Contains(vc.Issuer.ID, "did:jwk:") {
		signer["kid"] = vc.Issuer.ID + "#0"
	} else {
		signer["kid"] = vc.Issuer.ID + "#" + keyId
	}

	signer["alg"] = sigType

	para["subject"] = make(map[string]interface{})
	subject := para["subject"].(map[string]interface{})

	subject["iss"] = vc.Issuer.ID

	subject["iat"] = vc.Issued.Time.Unix()

	if vc.Expired != nil {
		subject["exp"] = vc.Expired.Time.Unix()
	}

	para["holder"] = make(map[string]interface{})
	holder := para["holder"].(map[string]interface{})
	holder["cnf"] = make(map[string]interface{})

	m, ok := vc.Subject.(verifiable.Subject)

	if !ok {

		sub, ok := vc.Subject.([]verifiable.Subject)

		if !ok {
			return nil, errors.New("No valid subject")
		} else {
			m = sub[0]
		}
	}

	c, ok := m.CustomFields["cnf"]
	cnf := make(map[string]interface{})
	if ok {
		cnf["jwk"] = c
		holder["cnf"] = cnf
		delete(m.CustomFields, "cnf")
	} else {
		if holderJwk != nil {
			cnf["jwk"] = holderJwk
			holder["cnf"] = cnf
		}
	}

	if status != nil && *status {
		url, _, purpose, index, err := s.getStatusListEntry(namespace, group, origin)

		if err != nil {
			return nil, err
		}

		st := make(map[string]interface{})
		st["statusPurpose"] = purpose
		st["statusListCredential"] = url
		st["statusListIndex"] = index
		m.CustomFields["status"] = st
	}

	subject["claims"] = m.CustomFields
	para["disclosureFrame"] = make(map[string]interface{})
	disclosureF := para["disclosureFrame"].(map[string]interface{})
	disclosureF["_sd"] = disclosureFrame

	b, err := json.Marshal(para)

	if err != nil {
		return nil, err
	}

	res, err := http.Post(s.sdjwtServiceUrl+"/issue", "application/json", bytes.NewBuffer(b))

	if err != nil {
		return nil, err
	}

	bodyBytes, err := io.ReadAll(res.Body)
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, errors.New(string(bodyBytes))
	}

	if err != nil {
		return nil, err
	}
	var result map[string]string

	err = json.Unmarshal(bodyBytes, &result)

	if err != nil {
		return nil, err
	}

	r, ok := result["sdjwt"]

	if !ok {
		return nil, errors.New("no result")
	}

	return &r, nil
}

func (s *Service) verifySdJwt(credential []byte, disclosureFrame []string, verifyKeyBinding bool, nonce, aud string) (*signer.VerifyResult, error) {
	para := make(map[string]interface{})
	println(string(credential))
	para["disclosureFrame"] = disclosureFrame
	para["sdjwt"] = string(credential)

	if verifyKeyBinding {
		para["verifyKeyBinding"] = verifyKeyBinding
		para["aud"] = aud
		para["nonce"] = nonce
	}

	b, err := json.Marshal(para)

	if err != nil {
		return nil, err
	}

	res, err := http.Post(s.sdjwtServiceUrl+"/verify", "application/json", bytes.NewBuffer(b))

	if err != nil {
		return nil, err
	}

	bodyBytes, err := io.ReadAll(res.Body)
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, errors.New(string(bodyBytes))
	}

	if err != nil {
		return nil, err
	}

	var result map[string]interface{}

	err = json.Unmarshal(bodyBytes, &result)

	if err != nil {
		return nil, err
	}

	valid := true

	for i, b := range result["result"].(map[string]interface{}) {
		valid = valid && b.(bool)

		if !valid {
			return &signer.VerifyResult{Valid: false}, errors.New(i + "not valid")
		}
	}

	return &signer.VerifyResult{Valid: valid, DisclosedCredential: result["claims"]}, nil
}

func (s *Service) parseCredential(vc []byte, proofCheck bool) (*verifiable.Credential, error) {
	var opts []verifiable.CredentialOpt
	opts = append(opts, verifiable.WithJSONLDDocumentLoader(s.docLoader))
	opts = append(opts, verifiable.WithStrictValidation())

	if proofCheck {
		opts = append(opts, verifiable.WithPublicKeyFetcher(s.keyFetcher))
		opts = append(opts, verifiable.WithEmbeddedSignatureSuites(
			jsonwebsignature2020.New(suite.WithVerifier(jsonwebsignature2020.NewPublicKeyVerifier())),
			ed25519signature2020.New(suite.WithVerifier(ed25519signature2020.NewPublicKeyVerifier())),
		))
	} else {
		opts = append(opts, verifiable.WithDisabledProofCheck())
	}

	return verifiable.ParseCredential(vc, opts...)
}

func (s *Service) parseCredentialWithProof(vc []byte) (*verifiable.Credential, error) {
	cred, err := verifiable.ParseCredential(
		vc,
		verifiable.WithPublicKeyFetcher(s.keyFetcher),
		verifiable.WithEmbeddedSignatureSuites(
			jsonwebsignature2020.New(suite.WithVerifier(jsonwebsignature2020.NewPublicKeyVerifier())),
			ed25519signature2020.New(suite.WithVerifier(ed25519signature2020.NewPublicKeyVerifier())),
		),
		verifiable.WithJSONLDDocumentLoader(s.docLoader),
		verifiable.WithStrictValidation(),
	)
	if err != nil {
		return nil, err
	}

	// check if the credential contains proof section
	if len(cred.Proofs) == 0 {
		return nil, errors.New("verifiable credential must have proof section")
	}

	return cred, nil
}

func validateCredentialSubject(subject interface{}) error {
	if subject == nil {
		return fmt.Errorf("verifiable credential must have subject")
	}

	switch subj := subject.(type) {
	case []verifiable.Subject:
		for _, sub := range subj {
			if sub.ID != "" {
				err := validateSubjectID(sub.ID)
				if err != nil {
					return err
				}
			}
		}
	case verifiable.Subject:
		if subj.ID != "" {
			err := validateSubjectID(subj.ID)
			if err != nil {
				return err
			}
		}
	case map[string]interface{}:
		if subj["id"] != nil {
			id, ok := subj["id"].(string)
			if !ok {
				return fmt.Errorf("invalid subject id format, string is expected")
			}
			err := validateSubjectID(id)
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown credential subject format")
	}

	return nil
}

func validateSubjectID(id string) error {
	s := strings.Split(id, ":")
	if len(s) < 2 {
		return fmt.Errorf("invalid subject id: must be URI")
	}

	if len(s[0]) == 0 || len(s[1]) == 0 {
		return fmt.Errorf("invalid subject id: must be URI")
	}

	return nil
}

func containContext(contexts []string, context string) bool {
	for _, c := range contexts {
		if c == context {
			return true
		}
	}
	return false
}

func splitEngineInfo(namespace, group, engine string) []EngineInfo {
	namespaces := strings.Split(namespace, ";")
	groups := strings.Split(group, ";")
	engines := strings.Split(engine, ";")

	info := make([]EngineInfo, 0)
	for i, v := range namespaces {
		eI := EngineInfo{
			Namespace: v,
		}

		if len(groups) > i {
			eI.Group = groups[i]
		}

		if len(engines) > i {
			eI.Engine = engines[i]
		}

		info = append(info, eI)
	}

	return info
}

func (s *Service) DidDoc(c context.Context, req *signer.DidRequest) (*signer.DidResponse, error) {
	logger := s.logger.With(
		zap.String("operation", "did"),
		zap.String("namespace", req.XNamespace),
		zap.String("group", req.XGroup),
		zap.String("engine", req.XEngine),
	)

	engines := splitEngineInfo(req.XNamespace, req.XGroup, req.XEngine)

	didErrorResponse := signer.DidResponse{
		ID:                 req.XDid,
		Controller:         req.XDid,
		VerificationMethod: make([]*signer.DIDVerificationMethod, 0),
		Service:            make([]*signer.ServiceEndpoint, 0),
	}

	var didresponse = &signer.DidResponse{
		ID:                 req.XDid,
		Controller:         req.XDid,
		VerificationMethod: make([]*signer.DIDVerificationMethod, 0),
		Service:            make([]*signer.ServiceEndpoint, 0),
	}

	for _, e := range engines {
		ctx := types.CryptoContext{
			Namespace: e.Namespace,
			Group:     e.Group,
			Context:   c,
			Engine:    e.Engine,
		}

		exist, err := s.cryptoProvider.IsCryptoContextExisting(ctx)

		if err != nil || !exist {
			logger.Error("namespace not found", zap.Error(err))

			return &didErrorResponse, nil
		}

		if exist {
			mthds, err := s.getVerficationMethods(ctx.Context, e.Namespace, e.Group, e.Engine, req.XDid)

			if err != nil {
				logger.Error("error getting keys.", zap.Error(err))
				return &didErrorResponse, nil
			}

			var input = make(map[string]interface{})
			input["did"] = req.XDid
			res, err := policy.GetPolicyResult(input, "SERVICE_POLICY")

			if err != nil {
				logger.Error("error getting keys.", zap.Error(err))
				return &didErrorResponse, err
			}

			if res != nil && err == nil {
				for _, x := range res["result"].([]interface{}) {
					var result = x.(map[string]interface{})
					didresponse.Service = append(didresponse.Service, &signer.ServiceEndpoint{
						ID:              result["id"].(string),
						Type:            result["type"].(string),
						ServiceEndpoint: result["serviceEndpoint"].(string),
					})
				}
			}

			didresponse.VerificationMethod = append(didresponse.VerificationMethod, mthds...)
		}
	}
	return didresponse, nil
}

func (s *Service) DidList(c context.Context, req *signer.DidListRequest) (*signer.DidListResponse, error) {
	logger := s.logger.With(
		zap.String("operation", "did"),
		zap.String("namespace", req.XNamespace),
		zap.String("group", req.XGroup),
		zap.String("engine", req.XEngine),
	)

	engines := splitEngineInfo(req.XNamespace, req.XGroup, req.XEngine)
	responseList := make([]*signer.DidListResponseItem, 0)
	for _, e := range engines {
		ctx := types.CryptoContext{
			Namespace: e.Namespace,
			Group:     e.Group,
			Context:   c,
			Engine:    e.Engine,
		}

		exist, err := s.cryptoProvider.IsCryptoContextExisting(ctx)

		if err != nil || !exist {
			logger.Error("namespace not found", zap.Error(err))

			return nil, &errors.Error{
				Err:     err,
				Kind:    errors.NotFound,
				Message: "Namespace not found.",
			}
		}

		if exist {
			keys, err := s.cryptoProvider.GetKeys(types.CryptoFilter{
				CryptoContext: ctx,
			})

			if err != nil {
				logger.Error("error getting keys.", zap.Error(err))
				return nil, &errors.Error{
					Err:     err,
					Kind:    errors.BadRequest,
					Message: "Error getting keys.",
				}
			}

			for _, k := range keys.Keys {
				jwk, err := k.GetJwk()
				if err != nil {
					logger.Error("error getting keys.", zap.Error(err))
					continue
				}
				bytes, err := json.Marshal(jwk)
				if err != nil {
					logger.Error("error getting keys.", zap.Error(err))
					continue
				}

				item := signer.DidListResponseItem{
					Name: k.Identifier.KeyId,
					Did:  "did:jwk:" + base64.RawURLEncoding.EncodeToString(bytes),
				}
				responseList = append(responseList, &item)
			}
		}
	}

	return &signer.DidListResponse{
		List: responseList,
	}, nil
}

func (s *Service) DidConfiguration(c context.Context, req *signer.DidConfiguration2) (any, error) {

	logger := s.logger.With(
		zap.String("operation", "did"),
		zap.String("namespace", req.XNamespace),
		zap.String("group", req.XGroup),
		zap.String("origin", req.XOrigin),
	)

	ctx := types.CryptoContext{
		Namespace: req.XNamespace,
		Group:     req.XGroup,
		Context:   c,
	}

	didConfigError := make(map[string]interface{}, 0)

	exist, err := s.cryptoProvider.IsCryptoContextExisting(ctx)

	if err != nil || !exist {
		logger.Error("namespace not found", zap.Error(err))

		return didConfigError, &errors.Error{
			Err:     err,
			Kind:    errors.NotFound,
			Message: "Namespace not found.",
		}
	}

	if exist {

		keys, err := s.cryptoProvider.GetKeys(types.CryptoFilter{
			CryptoContext: ctx,
		})

		if err != nil {
			logger.Error(err.Error())
			return didConfigError, &errors.Error{
				Kind:    errors.BadRequest,
				Message: "Keys not found.",
				Err:     err,
			}
		}

		now := time.Now()
		exp := time.Now().Add(time.Duration(time.Now().Year()))
		vc := make(map[string]interface{})
		vc["@context"] = []string{"https://www.w3.org/2018/credentials/v1", "https://identity.foundation/.well-known/did-configuration/v1"}
		vc["issuanceDate"] = now.Format(time.RFC3339Nano)
		vc["expirationDate"] = exp.Format(time.RFC3339Nano)
		vc["type"] = []string{"VerifiableCredential", "DomainLinkageCredential"}
		vc["credentialSubject"] = make(map[string]interface{}, 0)
		vc["credentialSubject"].(map[string]interface{})["origin"] = req.XOrigin

		vcArray := make([]any, 0)
		for _, k := range keys.Keys {
			jwk, err := k.GetJwk()
			if err != nil {
				logger.Error("error getting keys.", zap.Error(err))
				continue
			}
			bytes, err := json.Marshal(jwk)
			if err != nil {
				logger.Error("error getting keys.", zap.Error(err))
				continue
			}

			if req.XDid != nil {
				vc["issuer"] = req.XDid
				vc["credentialSubject"].(map[string]interface{})["id"] = req.XDid

				res, err := s.addProof(ctx.Context, vc, "ldp_vc", req.XNamespace, req.XGroup, k.Identifier.KeyId, req.XNonce, logger, req.XSignatureType, []string{})

				if err != nil {
					return didConfigError, &errors.Error{
						Kind:    errors.Internal,
						Message: "Error during vc creation",
					}
				}

				vcArray = append(vcArray, res)
				break
			} else {
				did := "did:jwk:" + base64.RawURLEncoding.EncodeToString(bytes)
				vc["issuer"] = did
				vc["credentialSubject"].(map[string]interface{})["id"] = did

				res, err := s.addProof(ctx.Context, vc, "ldp_vc", req.XNamespace, req.XGroup, k.Identifier.KeyId, req.XNonce, logger, req.XSignatureType, []string{})

				if err != nil {
					return didConfigError, &errors.Error{
						Kind:    errors.Internal,
						Message: "Error during vc creation",
					}
				}
				vcArray = append(vcArray, res)
			}
		}

		didconfig := make(map[string]interface{})

		didconfig["@context"] = "https://identity.foundation/.well-known/did-configuration/v1"
		didconfig["linked_dids"] = vcArray

		return didconfig, nil
	}
	return nil, &errors.Error{
		Kind:    errors.BadRequest,
		Message: "Nothing found.",
	}
}

func (s *Service) Jwks(ctx context.Context, req *signer.JwksRequest) (*signer.JwksResponse, error) {
	logger := s.logger.With(zap.String("operation", "jwks"))

	g := ""
	if req.XGroup != nil {
		g = *req.XGroup
	}

	engines := splitEngineInfo(req.XNamespace, g, req.XEngine)

	var barray = make([]any, 0)
	for _, e := range engines {

		cctx := types.CryptoContext{
			Context:   ctx,
			Namespace: e.Namespace,
			Group:     e.Group,
			Engine:    e.Engine,
		}

		if req.XGroup != nil {
			cctx.Group = *req.XGroup
		} else {
			cctx.Group = ""
		}

		filter := types.CryptoFilter{
			CryptoContext: cctx,
		}

		keys, err := s.cryptoProvider.GetKeys(filter)
		if err != nil {
			logger.Error("error getting keys", zap.Error(err))
			return &signer.JwksResponse{Keys: make([]any, 0)}, nil
		}

		for _, k := range keys.Keys {
			jwk, err := k.GetJwk()

			if err != nil {
				logger.Error("error transforming keys", zap.Error(err))
				return &signer.JwksResponse{Keys: make([]any, 0)}, nil
			}

			barray = append(barray, jwk)
		}
	}

	return &signer.JwksResponse{Keys: barray}, nil
}

func (s *Service) handleRequest(ctx context.Context, event event.Event) (*event.Event, error) {
	s.logger.Debug("Eventtype :" + event.Type())

	if strings.Compare(event.Type(), messaging.SignerServiceCreateKeyType) == 0 {
		return s.handleCreateKey(event)
	}

	if strings.Compare(event.Type(), messaging.SignerServiceSignTokenType) == 0 {
		return s.handleCreateToken(event)
	}

	if strings.Compare(event.Type(), messaging.SignerServiceSign) == 0 {

		return s.handleSigning(event)
	}

	errMsg := common.Reply{
		TenantId:  "Unknown",
		RequestId: "Unknown",
		Error: &common.Error{
			Status: 400,
			Msg:    "Unknown",
		},
	}

	e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceErrorType, s.createNatsReply(errMsg))

	return &e, err
}

func (s *Service) handleSigning(event event.Event) (*event.Event, error) {
	var signerServiceEvent messaging.CreateSigningRequest
	err := json.Unmarshal(event.Data(), &signerServiceEvent)

	reply := messaging.CreateSigningReply{
		Reply: common.Reply{
			TenantId:  signerServiceEvent.Namespace,
			RequestId: signerServiceEvent.RequestId,
		},
	}

	if err != nil {
		s.logger.Error(err.Error())
		reply.Error = &common.Error{
			Msg:    err.Error(),
			Status: 500,
		}
		e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceSignTokenType, s.createNatsReply(reply))
		return &e, err
	}

	if len(signerServiceEvent.Payload) == 0 {

		s.logger.Error("empty payload to sign")
		reply.Error = &common.Error{
			Msg:    "empty payload to sign",
			Status: 500,
		}
		e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceErrorType, s.createNatsReply(reply))
		return &e, err
	}

	key := types.CryptoIdentifier{
		CryptoContext: types.CryptoContext{
			Namespace: signerServiceEvent.Namespace,
			Group:     signerServiceEvent.Group,
			Context:   context.Background(),
		},
		KeyId: signerServiceEvent.Key,
	}

	b, err := s.cryptoProvider.Sign(key, signerServiceEvent.Payload)

	if err != nil {
		s.logger.Error(err.Error())
		reply.Error = &common.Error{
			Msg:    err.Error(),
			Status: 500,
		}
		e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceErrorType, s.createNatsReply(reply))
		return &e, err
	}

	reply.Signature = b
	e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceErrorType, s.createNatsReply(reply))
	return &e, err
}

func (s *Service) handleCreateToken(event event.Event) (*event.Event, error) {
	var signerServiceEvent messaging.CreateTokenRequest
	err := json.Unmarshal(event.Data(), &signerServiceEvent)

	reply := messaging.CreateTokenReply{
		Reply: common.Reply{
			TenantId:  signerServiceEvent.Namespace,
			RequestId: signerServiceEvent.RequestId,
		},
	}

	if err != nil {
		s.logger.Error(err.Error())
		reply.Error = &common.Error{
			Msg:    err.Error(),
			Status: 500,
		}
		e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceSignTokenType, s.createNatsReply(reply))
		return &e, err
	}

	var payload map[string]interface{} = make(map[string]interface{})
	if len(signerServiceEvent.Payload) > 0 {

		err = json.Unmarshal(signerServiceEvent.Payload, &payload)

		if err != nil {
			s.logger.Error(err.Error())
			reply.Error = &common.Error{
				Msg:    err.Error(),
				Status: 500,
			}
			e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceErrorType, s.createNatsReply(reply))
			return &e, err
		}
	}
	var header map[string]interface{} = make(map[string]interface{})
	if len(signerServiceEvent.Header) > 0 {
		err = json.Unmarshal(signerServiceEvent.Header, &header)

		if err != nil {
			s.logger.Error(err.Error())
			reply.Error = &common.Error{
				Msg:    err.Error(),
				Status: 500,
			}
			e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceErrorType, s.createNatsReply(reply))
			return &e, err
		}
	}

	tok := jwt.New()

	for k, i := range payload {
		tok.Set(k, i)
	}

	tok.Set(jwt.IssuedAtKey, time.Now().Unix())

	headers := jws.NewHeaders()
	for k, i := range header {
		headers.Set(k, i)
	}

	_, selfOk := header["jwk"]

	key, err := s.cryptoProvider.GetKey(types.CryptoIdentifier{
		CryptoContext: types.CryptoContext{
			Namespace: signerServiceEvent.Namespace,
			Group:     signerServiceEvent.Group,
			Context:   context.Background(),
		},
		KeyId: signerServiceEvent.Key,
	})

	if err != nil {
		s.logger.Error(err.Error())
		reply.Error = &common.Error{
			Msg:    err.Error(),
			Status: 500,
		}
		e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceErrorType, s.createNatsReply(reply))
		return &e, err
	}

	k, err := key.GetJwk()

	var alg jwa.KeyAlgorithm

	if key.KeyType == types.Ecdsap256 {
		alg = jwa.ES256
	}

	if key.KeyType == types.Rsa2048 {
		alg = jwa.PS256
	}

	if key.KeyType == types.Rsa3072 {
		alg = jwa.PS256
	}

	if key.KeyType == types.Rsa4096 {
		alg = jwa.PS256
	}

	if key.KeyType == types.Ed25519 {
		alg = jwa.EdDSA
	}

	if key.KeyType == types.Ecdsap384 {
		alg = jwa.ES384
	}

	if key.KeyType == types.Ecdsap521 {
		alg = jwa.ES512
	}

	if alg == nil {
		s.logger.Error("Keytype unsupported: " + string(key.KeyType))
		reply.Error = &common.Error{
			Msg:    err.Error(),
			Status: 500,
		}
		e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceErrorType, s.createNatsReply(reply))
		return &e, err
	}

	k.Set("alg", alg)

	_, kOk := headers.Get("kid")

	if !kOk && !selfOk {
		bytes, err := json.Marshal(k)

		if err != nil {
			s.logger.Error(err.Error())
			reply.Error = &common.Error{
				Msg:    err.Error(),
				Status: 500,
			}
			e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceErrorType, s.createNatsReply(reply))
			return &e, err
		}

		kid := strings.Join(
			[]string{
				"did:jwk:" + base64.RawURLEncoding.EncodeToString(bytes),
				"0"},
			"#")
		headers.Set("kid", kid)
	}

	if selfOk {
		if err != nil {
			s.logger.Error(err.Error())
			reply.Error = &common.Error{
				Msg:    err.Error(),
				Status: 500,
			}
			e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceErrorType, s.createNatsReply(reply))
			return &e, err
		}

		err = headers.Set("jwk", k)

		if err != nil {
			s.logger.Error(err.Error())
			reply.Error = &common.Error{
				Msg:    err.Error(),
				Status: 500,
			}
			e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceErrorType, s.createNatsReply(reply))
			return &e, err
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(alg, signerServiceEvent.Namespace+"/"+signerServiceEvent.Group+":"+signerServiceEvent.Key, jws.WithProtectedHeaders(headers)))

	if err != nil {
		s.logger.Error(err.Error())
		reply.Error = &common.Error{
			Msg:    err.Error(),
			Status: 500,
		}
		e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceErrorType, s.createNatsReply(reply))
		return &e, err
	}
	s.logger.Info(string(signed))

	reply.Token = signed

	e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceSignTokenType, s.createNatsReply(reply))
	return &e, err
}

func (s *Service) handleCreateKey(event event.Event) (*event.Event, error) {
	var signerServiceEvent messaging.CreateKeyRequest
	err := json.Unmarshal(event.Data(), &signerServiceEvent)

	if err != nil {
		s.logger.Error(err.Error())
	}

	ctx := types.CryptoContext{
		Namespace: signerServiceEvent.Namespace,
		Group:     signerServiceEvent.Group,
		Context:   context.Background(),
	}

	reply := common.Reply{
		TenantId:  signerServiceEvent.Namespace,
		RequestId: signerServiceEvent.RequestId,
	}

	b, err := s.cryptoProvider.IsCryptoContextExisting(ctx)

	if err != nil {
		s.logger.Error(err.Error())
		reply.Error = &common.Error{
			Msg:    err.Error(),
			Status: 500,
		}

		e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceErrorType, s.createNatsReply(reply))
		return &e, err
	}

	if !b {
		err = s.cryptoProvider.CreateCryptoContext(ctx)
		if err != nil {
			s.logger.Error(err.Error())
			reply.Error = &common.Error{
				Msg:    err.Error(),
				Status: 500,
			}
			e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceErrorType, s.createNatsReply(reply))
			return &e, err
		}
	}

	identifier := types.CryptoIdentifier{
		CryptoContext: ctx,
		KeyId:         signerServiceEvent.Key,
	}

	b, err = s.cryptoProvider.IsKeyExisting(identifier)

	if err != nil {
		s.logger.Error(err.Error())
		reply.Error = &common.Error{
			Msg:    err.Error(),
			Status: 500,
		}
		e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceErrorType, s.createNatsReply(reply))
		return &e, err
	}

	if !b {
		parameter := types.CryptoKeyParameter{
			Identifier: identifier,
			KeyType:    types.KeyType(signerServiceEvent.Type),
		}

		err = s.cryptoProvider.GenerateKey(parameter)
		if err != nil {
			s.logger.Error(err.Error())
			reply.Error = &common.Error{
				Msg:    err.Error(),
				Status: 500,
			}
			e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceErrorType, s.createNatsReply(reply))
			return &e, err
		}
	}

	rep := messaging.CreateKeyReply{
		Reply: reply,
	}

	e, err := cloudeventprovider.NewEvent(event.Source(), messaging.SignerServiceCreateKeyType, s.createNatsReply(rep))
	return &e, err
}

func (s *Service) createNatsReply(msg interface{}) []byte {

	b, err := json.Marshal(msg)

	if err != nil {
		s.logger.Error("error in json marshalling")
	}
	return b
}

func (s *Service) Listen() {
	for {
		if err := s.messageClient.Reply(s.handleRequest); err != nil {
			s.logger.Error(err.Error())
		}
	}
}

func (s *Service) StartMessaging(group *sync.WaitGroup) {
	if s.natsHost == "" {
		s.logger.Info("messaging is not configured")
		return
	}

	s.logger.Info(fmt.Sprintf("start messaging %s", s.natsHost))
	defer group.Done()

	client, err := cloudeventprovider.New(
		cloudeventprovider.Config{Protocol: cloudeventprovider.ProtocolTypeNats, Settings: cloudeventprovider.NatsConfig{
			Url:          s.natsHost,
			TimeoutInSec: time.Minute,
		}},
		cloudeventprovider.ConnectionTypeRep,
		s.natsTopic,
	)
	if err != nil {
		s.logger.Fatal(err.Error())
	}

	s.messageClient = client

	go s.Listen()
}
