package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"time"
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
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrInvalid, path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%w: %s is writable by group or others", ErrInvalid, path)
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
