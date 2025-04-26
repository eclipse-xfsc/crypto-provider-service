package config

import "time"

type Config struct {
	HTTP     httpConfig
	Metrics  metricsConfig
	Auth     authConfig
	Cred     credentialsConfig
	Train    trainConfig
	Nats     natsConfig
	SdJwt    sdjwtConfig
	LogLevel string `envconfig:"LOG_LEVEL" default:"INFO"`
	Profile  string `envconfig:"PROFILE" default:"DEBUG"`
	Protocol string `envconfig:"PROTOCOL" default:"nats"`
}

type sdjwtConfig struct {
	Url string `envconfig:"SDJWT_SERVICE_URL" `
}

type httpConfig struct {
	Host         string        `envconfig:"HTTP_HOST"`
	Port         string        `envconfig:"HTTP_PORT" default:"8080"`
	IdleTimeout  time.Duration `envconfig:"HTTP_IDLE_TIMEOUT" default:"120s"`
	ReadTimeout  time.Duration `envconfig:"HTTP_READ_TIMEOUT" default:"10s"`
	WriteTimeout time.Duration `envconfig:"HTTP_WRITE_TIMEOUT" default:"10s"`
}

type natsConfig struct {
	Host        string `envconfig:"NATS_HOST" required:"false"`
	Topic       string `envconfig:"NATS_TOPIC" required:"false"`
	StatusTopic string `envconfig:"NATS_STATUS_TOPIC" required:"false"`
}

type metricsConfig struct {
	Addr string `envconfig:"METRICS_ADDR" default:":2112"`
}

type authConfig struct {
	Enabled         bool          `envconfig:"AUTH_ENABLED" default:"false"`
	JwkURL          string        `envconfig:"AUTH_JWK_URL"`
	RefreshInterval time.Duration `envconfig:"AUTH_REFRESH_INTERVAL" default:"1h"`
}

type credentialsConfig struct {
	Verifiers []string `envconfig:"CREDENTIAL_VERIFIERS"`
}

type trainConfig struct {
	Addr         string   `envconfig:"TRAIN_ADDR"`
	TrustSchemes []string `envconfig:"TRAIN_TRUST_SCHEMES"`
}
