package wire

import "testing"

func TestParseAndFormatUsage(t *testing.T) {
	bits, err := ParseUsage("Encrypt, decrypt,export")
	if err != nil || FormatUsage(bits) != "encrypt,decrypt,export" {
		t.Fatalf("%v %v", bits, err)
	}
	if _, err := ParseUsage("encrypt,bogus"); err == nil {
		t.Fatal("unknown usage accepted")
	}
	if _, err := ParseUsage(""); err == nil {
		t.Fatal("empty usage accepted")
	}
	if AlgName(AlgAES256GCM) != "aes-256-gcm" || AlgName(0xfffe) != "0xfffe" {
		t.Fatal("alg names")
	}
}
