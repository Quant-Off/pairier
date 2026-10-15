package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kmsd.json")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAndValidate(t *testing.T) {
	c, err := Load(write(t, `{"dir":"/var/lib/kms","core":"/usr/bin/kms-core","listen":"127.0.0.1:7443","allow_unlocked_memory":false,"timeout":"20s"}`, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if c.Dir != "/var/lib/kms" || c.Listen != "127.0.0.1:7443" || c.AllowUnlockedMemory == nil || *c.AllowUnlockedMemory || c.TimeoutDuration(time.Second) != 20*time.Second {
		t.Fatalf("%+v", c)
	}
	for name, body := range map[string]string{
		"unknown field": `{"dir":"x","extra":1}`,
		"bad listen":    `{"listen":"nohost"}`,
		"dns listen":    `{"listen":"localhost:1"}`,
		"bad timeout":   `{"timeout":"-1s"}`,
		"trailing":      `{"dir":"x"}{}`,
	} {
		if _, err := Load(write(t, body, 0o600)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	loose := write(t, `{"dir":"x"}`, 0o600)
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(loose); !errors.Is(err, ErrInvalid) {
		t.Fatalf("world writable config accepted: %v", err)
	}
	c, err = Load(write(t, `{"listen":":7443"}`, 0o644))
	if err != nil || c.TimeoutDuration(3*time.Second) != 3*time.Second {
		t.Fatalf("%+v %v", c, err)
	}
}
