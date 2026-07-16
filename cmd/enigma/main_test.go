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
