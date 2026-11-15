package wire

import (
	"errors"
	"fmt"
	"strings"
)

type UsageName struct {
	Name string
	Bit  uint32
}

var Usages = []UsageName{
	{"encrypt", UsageEncrypt},
	{"decrypt", UsageDecrypt},
	{"sign", UsageSign},
	{"verify", UsageVerify},
	{"wrap", UsageWrap},
	{"unwrap", UsageUnwrap},
	{"derive", UsageDerive},
	{"decapsulate", UsageDecapsulate},
	{"export", UsageExport},
}

var algNames = map[uint16]string{
	AlgAES256GCM:          "aes-256-gcm",
	AlgECDSAP256SHA256:    "ecdsa-p256-sha256",
	AlgECDSAP384SHA384:    "ecdsa-p384-sha384",
	AlgEd25519:            "ed25519",
	AlgDHKEMP256:          "dhkem-p256",
	AlgMLDSA65:            "ml-dsa-65",
	AlgMLDSA87:            "ml-dsa-87",
	AlgMLKEM768:           "ml-kem-768",
	AlgMLKEM1024:          "ml-kem-1024",
	AlgHybridP256MLKEM768: "hybrid-p256-ml-kem-768",
	AlgMLKEM768P256:       "mlkem768-p256",
}

func AlgName(alg uint16) string {
	if s, ok := algNames[alg]; ok {
		return s
	}
	return fmt.Sprintf("0x%04x", alg)
}

func ParseUsage(s string) (uint32, error) {
	var bits uint32
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		found := false
		for _, u := range Usages {
			if u.Name == part {
				bits |= u.Bit
				found = true
				break
			}
		}
		if !found {
			return 0, fmt.Errorf("unknown usage %q", part)
		}
	}
	if bits == 0 {
		return 0, errors.New("usage list is empty")
	}
	return bits, nil
}

func FormatUsage(bits uint32) string {
	var parts []string
	for _, u := range Usages {
		if bits&u.Bit != 0 {
			parts = append(parts, u.Name)
		}
	}
	return strings.Join(parts, ",")
}
