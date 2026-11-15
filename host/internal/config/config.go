package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/Quant-Off/pairier/host/internal/fsx"
)

var ErrInvalid = errors.New("config: invalid configuration")

type Config struct {
	Dir                 string `json:"dir"`
	Core                string `json:"core"`
	Listen              string `json:"listen"`
	AllowUnlockedMemory *bool  `json:"allow_unlocked_memory,omitempty"`
	Timeout             string `json:"timeout,omitempty"`
}

func Load(path string) (*Config, error) {
	if err := fsx.CheckNotWritableByOthers(path); err != nil {
		if errors.Is(err, fsx.ErrInsecure) {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) Validate() error {
	if c.Listen != "" {
		host, port, err := net.SplitHostPort(c.Listen)
		if err != nil || port == "" {
			return fmt.Errorf("%w: listen must be host:port", ErrInvalid)
		}
		if host != "" && net.ParseIP(host) == nil {
			return fmt.Errorf("%w: listen host must be an ip address", ErrInvalid)
		}
	}
	if c.Timeout != "" {
		d, err := time.ParseDuration(c.Timeout)
		if err != nil || d <= 0 {
			return fmt.Errorf("%w: timeout must be a positive duration", ErrInvalid)
		}
	}
	return nil
}

func (c *Config) TimeoutDuration(def time.Duration) time.Duration {
	if c.Timeout == "" {
		return def
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil || d <= 0 {
		return def
	}
	return d
}
