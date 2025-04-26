package config

import (
	"time"
)

var DefaultHTTPTimeout = 5 * time.Second

var DefaultTokenExpiry = 5 * time.Minute

// DefaultLeeway allows n minutes time difference (clocks out of sync etc)
var DefaultLeeway = 5 * time.Minute
