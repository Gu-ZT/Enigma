package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"os"
	"strings"
	"testing"
)

func TestKeygen(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run(context.Background(), []string{"keygen"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(stdout.String()))
	if err != nil {
		t.Fatalf("keygen output: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d", len(key))
	}
}

func TestHelp(t *testing.T) {
	var stdout bytes.Buffer
	if err := run(context.Background(), []string{"help"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "enigma server") {
		t.Fatalf("help output = %q", stdout.String())
	}
}

func TestRequiredArguments(t *testing.T) {
	key := strings.Repeat("00", 32)
	tests := [][]string{
		{"server"},
		{"client", "-key", key, "-target", "example.com:443"},
		{"client", "-key", key, "-server", "127.0.0.1:8443"},
	}
	for _, args := range tests {
		if err := run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("arguments %v succeeded", args)
		}
	}
}

func TestTargetPolicy(t *testing.T) {
	policy, err := buildTargetPolicy([]string{"example.com:443", "127.0.0.1:22"})
	if err != nil {
		t.Fatal(err)
	}
	if !policy("example.com:443") || policy("example.com:80") {
		t.Fatal("target policy mismatch")
	}
	policy, err = buildTargetPolicy([]string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	if policy != nil {
		t.Fatal("wildcard policy should allow all")
	}
	if _, err := buildTargetPolicy([]string{"missing-port"}); err == nil {
		t.Fatal("invalid target policy accepted")
	}
}

func TestTargetPolicyPatterns(t *testing.T) {
	policy, err := buildTargetPolicy([]string{"*.example.com:443", "192.0.2.0/24:*", "[2001:db8::/64]:8443"})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]bool{
		"api.example.com:443":      true,
		"deep.api.example.com:443": true,
		"example.com:443":          false,
		"api.example.com:80":       false,
		"192.0.2.12:1":             true,
		"192.0.2.12:65535":         true,
		"192.0.3.12:443":           false,
		"[2001:db8::1]:8443":       true,
		"[2001:db9::1]:8443":       false,
		"example.net:443":          false,
	}
	for address, want := range tests {
		if got := policy(address); got != want {
			t.Errorf("policy(%q) = %v, want %v", address, got, want)
		}
	}

	for _, value := range []string{"*.example.com", "10.0.0.0/99:443", "10.0.0.0/8:0", "foo*bar:443", "[2001:db8::/129]:443"} {
		if _, err := buildTargetPolicy([]string{value}); err == nil {
			t.Errorf("invalid target rule %q accepted", value)
		}
	}
}

func TestKeyFile(t *testing.T) {
	path := t.TempDir() + "/key.txt"
	if err := os.WriteFile(path, []byte(strings.Repeat("42", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	values := addCodecFlags(flags)
	if err := flags.Parse([]string{"-key-file", path}); err != nil {
		t.Fatal(err)
	}
	config, err := values.config()
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Key) != 32 || config.Key[0] != 0x42 {
		t.Fatal("key file was not decoded")
	}
}

func TestTransportFlagValidation(t *testing.T) {
	serverFlags := flag.NewFlagSet("server-transport", flag.ContinueOnError)
	server := addServerTransportFlags(serverFlags)
	if err := serverFlags.Parse([]string{"-tls"}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.wrapper(0); err == nil {
		t.Fatal("TLS server without certificate accepted")
	}

	clientFlags := flag.NewFlagSet("client-transport", flag.ContinueOnError)
	client := addClientTransportFlags(clientFlags)
	if err := clientFlags.Parse([]string{"-tls-ca-file", "missing.pem"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.wrapper("example.com:8443", 0); err == nil {
		t.Fatal("TLS client option without -tls accepted")
	}

	if got := serverHost("[2001:db8::1]:8443"); got != "2001:db8::1" {
		t.Fatalf("serverHost = %q", got)
	}
}

func TestUDPFlagValidation(t *testing.T) {
	key := strings.Repeat("00", 32)
	serverErr := run(context.Background(), []string{"server", "-udp", "-key", key}, &bytes.Buffer{}, &bytes.Buffer{})
	if serverErr == nil || !strings.Contains(serverErr.Error(), "requires -mux") {
		t.Fatalf("server UDP error = %v", serverErr)
	}
	clientErr := run(context.Background(), []string{
		"client", "-udp", "-server", "127.0.0.1:8443", "-target", "127.0.0.1:53", "-key", key,
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if clientErr == nil || !strings.Contains(clientErr.Error(), "requires -mux") {
		t.Fatalf("client UDP error = %v", clientErr)
	}
}

func TestCodecProfiles(t *testing.T) {
	key := strings.Repeat("42", 32)
	tests := []struct {
		name            string
		args            []string
		maxPayload      int
		maxPadding      int
		maxCoverPadding int
	}{
		{name: "standard", args: []string{"-key", key}, maxPayload: 16 * 1024},
		{name: "balanced", args: []string{"-key", key, "-profile", "balanced"}, maxPayload: 16 * 1024, maxPadding: 64, maxCoverPadding: 32},
		{name: "compact", args: []string{"-key", key, "-profile", "compact"}, maxPayload: 32 * 1024},
		{name: "high-padding", args: []string{"-key", key, "-profile", "high-padding"}, maxPayload: 8 * 1024, maxPadding: 512, maxCoverPadding: 256},
		{name: "override", args: []string{"-key", key, "-profile", "balanced", "-padding-min", "0", "-padding-max", "0"}, maxPayload: 16 * 1024, maxCoverPadding: 32},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			flags := flag.NewFlagSet(test.name, flag.ContinueOnError)
			values := addCodecFlags(flags)
			if err := flags.Parse(test.args); err != nil {
				t.Fatal(err)
			}
			config, err := values.config()
			if err != nil {
				t.Fatal(err)
			}
			if config.MaxPayload != test.maxPayload || config.MaxPadding != test.maxPadding || config.MaxCoverPadding != test.maxCoverPadding {
				t.Fatalf("profile config = payload %d padding %d cover %d", config.MaxPayload, config.MaxPadding, config.MaxCoverPadding)
			}
		})
	}

	flags := flag.NewFlagSet("invalid-profile", flag.ContinueOnError)
	values := addCodecFlags(flags)
	if err := flags.Parse([]string{"-key", key, "-profile", "unknown"}); err != nil {
		t.Fatal(err)
	}
	if _, err := values.config(); err == nil {
		t.Fatal("unknown profile accepted")
	}
}
