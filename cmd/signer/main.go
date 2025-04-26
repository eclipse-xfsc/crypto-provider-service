package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/piprate/json-gold/ld"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
	"golang.org/x/sync/errgroup"

	goahealth "github.com/eclipse-xfsc/crypto-provider-service/gen/health"
	goahealthsrv "github.com/eclipse-xfsc/crypto-provider-service/gen/http/health/server"
	goaopenapisrv "github.com/eclipse-xfsc/crypto-provider-service/gen/http/openapi/server"
	goasignersrv "github.com/eclipse-xfsc/crypto-provider-service/gen/http/signer/server"
	"github.com/eclipse-xfsc/crypto-provider-service/gen/openapi"
	goasigner "github.com/eclipse-xfsc/crypto-provider-service/gen/signer"
	"github.com/eclipse-xfsc/crypto-provider-service/internal/config"
	"github.com/eclipse-xfsc/crypto-provider-service/internal/service"
	"github.com/eclipse-xfsc/crypto-provider-service/internal/service/health"
	"github.com/eclipse-xfsc/crypto-provider-service/internal/service/signer"
	"github.com/eclipse-xfsc/crypto-provider-service/internal/verify"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/engine/core"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/engine/core/types"
	sjwt "gitlab.eclipse.org/eclipse/xfsc/libraries/crypto/jwt"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/golib/auth"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/golib/graceful"
)

var Version = os.Getenv("VERSION")

func main() {
	var wg sync.WaitGroup
	// load configuration from environment
	var cfg config.Config
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatalf("cannot load configuration: %v", err)
	}

	logger, err := createLogger(cfg.LogLevel)
	if err != nil {
		log.Fatalln(err)
	}
	defer logger.Sync() //nolint:errcheck

	var engine types.CryptoProvider
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}

	exPath := filepath.Dir(ex)
	enginePath := os.Getenv("ENGINE_PATH")
	logger.Log(zap.InfoLevel, "Start Service with Engine "+enginePath)

	if cfg.Profile == "DEBUG:LOCAL" {
		engine = core.CreateCryptoEngine(path.Join(exPath, "../../.engines/.local/local-provider.so"))
	} else {
		if cfg.Profile == "DEBUG:VAULT" {
			engine = core.CreateCryptoEngine(path.Join(exPath, "../../.engines/.vault/hashicorp-vault-provider.so"))
		} else {
			if _, err := os.Stat(enginePath); err == nil || os.IsExist(err) {
				logger.Log(zap.InfoLevel, "Load Engine...")
				engine = core.CreateCryptoEngine(enginePath)
			} else {
				panic("Engine not exists.")
			}
		}
	}
	sjwt.EnableCryptoProvider(engine, true, false)
	// create logger

	logger.Info("signer service started", zap.String("version", Version), zap.String("goa", goa.Version()))

	httpClient := httpClient()

	if err != nil {
		logger.Fatal("cannot initialize vault client", zap.Error(err))
	}

	verifiers, err := verify.New(cfg.Cred.Verifiers, httpClient, cfg.Train.Addr, cfg.Train.TrustSchemes)
	if err != nil {
		logger.Fatal("instantiating additional credential verifiers failed", zap.Error(err))
	}

	// create services
	var (
		signerSvc goasigner.Service
		healthSvc goahealth.Service
	)
	{
		supported := make([]string, 0)
		for _, s := range engine.GetSupportedKeysAlgs() {
			supported = append(supported, string(s))
		}
		// create jsonld document loader which the signer uses to resolve jsonld contexts
		docLoader := ld.NewCachingDocumentLoader(ld.NewDefaultDocumentLoader(httpClient))
		signerSvc = signer.New(engine, verifiers, supported, docLoader, logger, cfg.Nats.Host, cfg.Nats.Topic, cfg.Nats.StatusTopic, &wg, cfg.SdJwt.Url)
		healthSvc = health.New(Version)
	}

	// create endpoints
	var (
		signerEndpoints  *goasigner.Endpoints
		healthEndpoints  *goahealth.Endpoints
		openapiEndpoints *openapi.Endpoints
	)
	{
		signerEndpoints = goasigner.NewEndpoints(signerSvc)
		healthEndpoints = goahealth.NewEndpoints(healthSvc)
		openapiEndpoints = openapi.NewEndpoints(nil)
	}

	// Provide the transport specific request decoder and response encoder.
	// The goa http package has built-in support for JSON, XML and gob.
	// Other encodings can be used by providing the corresponding functions,
	// see goa.design/implement/encoding.
	var (
		dec = goahttp.RequestDecoder
		enc = goahttp.ResponseEncoder
	)

	// Build the service HTTP request multiplexer and configure it to serve
	// HTTP requests to the service endpoints.
	mux := goahttp.NewMuxer()

	// Wrap the endpoints with the transport specific layers. The generated
	// server packages contains code generated from the design which maps
	// the service input and output data structures to HTTP requests and
	// responses.
	var (
		signerServer  *goasignersrv.Server
		healthServer  *goahealthsrv.Server
		openapiServer *goaopenapisrv.Server
	)
	{
		signerServer = goasignersrv.New(signerEndpoints, mux, dec, enc, nil, errFormatter)
		healthServer = goahealthsrv.New(healthEndpoints, mux, dec, enc, nil, errFormatter)
		openapiServer = goaopenapisrv.New(openapiEndpoints, mux, dec, enc, nil, errFormatter, nil, nil)
	}

	// set custom request decoder, so that request body bytes are simply
	// read and not decoded in some other way.
	// Can these definitions be simplified or taken out into a function for better readability?
	//{
	//	signerServer.VerifyCredential = goasignersrv.NewVerifyCredentialHandler(
	//		signerEndpoints.VerifyCredential,
	//		mux,
	//		decoder.RequestDecoder,
	//		enc,
	//		nil,
	//		errFormatter,
	//	)
	//
	//	signerServer.VerifyPresentation = goasignersrv.NewVerifyPresentationHandler(
	//		signerEndpoints.VerifyPresentation,
	//		mux,
	//		decoder.RequestDecoder,
	//		enc,
	//		nil,
	//		errFormatter,
	//	)
	//}

	// Apply Authentication middleware if enabled
	if cfg.Auth.Enabled {
		m, err := auth.NewMiddleware(cfg.Auth.JwkURL, cfg.Auth.RefreshInterval, httpClient)
		if err != nil {
			logger.Fatal("failed to create authentication middleware", zap.Error(err))
		}
		signerServer.Use(m.Handler())
	}

	// Configure the mux.
	goasignersrv.Mount(mux, signerServer)
	goahealthsrv.Mount(mux, healthServer)
	goaopenapisrv.Mount(mux, openapiServer)
	// expose metrics
	go exposeMetrics(cfg.Metrics.Addr, logger)

	var handler http.Handler = mux
	srv := &http.Server{
		Addr:              cfg.HTTP.Host + ":" + cfg.HTTP.Port,
		Handler:           handler,
		ReadHeaderTimeout: cfg.HTTP.ReadTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
	}

	g, ctx := errgroup.WithContext(context.Background())
	g.Go(func() error {
		if err := graceful.Shutdown(ctx, srv, 20*time.Second); err != nil {
			logger.Error("server shutdown error", zap.Error(err))
			return err
		}
		return errors.New("server stopped successfully")
	})

	if err := g.Wait(); err != nil {
		logger.Error("run group stopped", zap.Error(err))
	}
	wg.Wait()

	logger.Info("bye bye")
}

func createLogger(logLevel string, opts ...zap.Option) (*zap.Logger, error) {
	var level = zapcore.InfoLevel
	if logLevel != "" {
		err := level.UnmarshalText([]byte(logLevel))
		if err != nil {
			return nil, err
		}
	}

	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(level)
	config.DisableStacktrace = true
	config.EncoderConfig.TimeKey = "ts"
	config.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
	return config.Build(opts...)
}

func errFormatter(ctx context.Context, e error) goahttp.Statuser {
	return service.NewErrorResponse(ctx, e)
}

func httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			TLSHandshakeTimeout: 10 * time.Second,
			IdleConnTimeout:     60 * time.Second,
		},
		Timeout: 10 * time.Second,
	}
}

func exposeMetrics(addr string, logger *zap.Logger) {
	promMux := http.NewServeMux()
	promMux.Handle("/metrics", promhttp.Handler())
	logger.Info(fmt.Sprintf("exposing prometheus metrics at %s/metrics", addr))
	if err := http.ListenAndServe(addr, promMux); err != nil { //nolint:gosec
		logger.Error("error exposing prometheus metrics", zap.Error(err))
	}
}
