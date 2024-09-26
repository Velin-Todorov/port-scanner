package config

import (
	"flag"
	"time"
)

// Config holds the configuration for the port scanner
type Config struct {
	Host string
	Port string
	// TODO: add more as the project progresses.
}