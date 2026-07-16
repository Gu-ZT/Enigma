package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"Enigma/internal/app"
	"Enigma/internal/tunnel"
	"Enigma/pkg/enigma"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "keygen":
		return runKeygen(args[1:], stdout, stderr)
	case "server":
		return runServer(ctx, args[1:], stderr)
	case "client":
		return runClient(ctx, args[1:], stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
		return nil
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usageText)
	}
}

func runKeygen(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("keygen does not accept positional arguments")
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	fmt.Fprintln(stdout, hex.EncodeToString(key))
	return nil
}

func runServer(ctx context.Context, args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("server", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listenAddress := flags.String("listen", ":8443", "TCP listen address")
	dialTimeout := flags.Duration("dial-timeout", 10*time.Second, "target dial timeout")
	replayCapacity := flags.Int("replay-capacity", 65536, "maximum live client nonces")
	replayTTL := flags.Duration("replay-ttl", 2*time.Minute, "client nonce retention")
	var allowedTargets stringList
	flags.Var(&allowedTargets, "allow-target", "allowed canonical host:port; repeatable, empty allows all")
	codecFlags := addCodecFlags(flags)
	handshakeFlags := addHandshakeFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("server does not accept positional arguments")
	}
	codec, err := codecFlags.config()
	if err != nil {
		return err
	}
	guard, err := tunnel.NewReplayGuard(*replayCapacity, *replayTTL)
	if err != nil {
		return err
	}
	tunnelConfig := tunnel.Config{
		Codec:            codec,
		HandshakeTimeout: handshakeFlags.timeout,
		MaxClockSkew:     handshakeFlags.maxClockSkew,
		ReplayGuard:      guard,
	}
	if err := tunnelConfig.ValidateServer(); err != nil {
		return err
	}
	allowTarget, err := buildTargetPolicy(allowedTargets)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *listenAddress, err)
	}
	logger := log.New(stderr, "enigma-server: ", log.LstdFlags)
	logger.Printf("listening on %s", listener.Addr())
	return app.ServeServer(ctx, listener, app.ServerConfig{
		Tunnel:      tunnelConfig,
		DialTimeout: *dialTimeout,
		Logger:      logger,
		AllowTarget: allowTarget,
	})
}

func runClient(ctx context.Context, args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listenAddress := flags.String("listen", "127.0.0.1:1080", "local TCP listen address")
	serverAddress := flags.String("server", "", "ETPH/1 server host:port")
	targetAddress := flags.String("target", "", "fixed target host:port")
	socks5 := flags.Bool("socks5", false, "serve a local no-auth SOCKS5 listener instead of a fixed target")
	socks5Timeout := flags.Duration("socks5-timeout", 10*time.Second, "local SOCKS5 handshake timeout")
	dialTimeout := flags.Duration("dial-timeout", 10*time.Second, "server dial timeout")
	codecFlags := addCodecFlags(flags)
	handshakeFlags := addHandshakeFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("client does not accept positional arguments")
	}
	if *serverAddress == "" {
		return fmt.Errorf("client -server is required")
	}
	if *socks5 {
		if *targetAddress != "" {
			return fmt.Errorf("-target cannot be used with -socks5")
		}
		if *socks5Timeout < 0 {
			return fmt.Errorf("-socks5-timeout must not be negative")
		}
	} else if err := tunnel.ValidateTargetAddress(*targetAddress); err != nil {
		return fmt.Errorf("invalid -target: %w", err)
	}
	codec, err := codecFlags.config()
	if err != nil {
		return err
	}
	tunnelConfig := tunnel.Config{
		Codec:            codec,
		HandshakeTimeout: handshakeFlags.timeout,
		MaxClockSkew:     handshakeFlags.maxClockSkew,
	}
	if err := tunnelConfig.ValidateClient(); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *listenAddress, err)
	}
	logger := log.New(stderr, "enigma-client: ", log.LstdFlags)
	if *socks5 {
		logger.Printf("SOCKS5 listening on %s through %s", listener.Addr(), *serverAddress)
	} else {
		logger.Printf("listening on %s, forwarding to %s through %s", listener.Addr(), *targetAddress, *serverAddress)
	}
	return app.ServeClient(ctx, listener, app.ClientConfig{
		Tunnel:                tunnelConfig,
		ServerAddress:         *serverAddress,
		TargetAddress:         *targetAddress,
		TargetSelector:        selectTargetSelector(*socks5),
		LocalHandshakeTimeout: *socks5Timeout,
		DialTimeout:           *dialTimeout,
		Logger:                logger,
	})
}

func selectTargetSelector(socks5 bool) app.TargetSelector {
	if socks5 {
		return app.SOCKS5Selector
	}
	return nil
}

type codecFlagValues struct {
	keyHex          *string
	keyFile         *string
	minPadding      *int
	maxPadding      *int
	minCoverPadding *int
	maxCoverPadding *int
	maxPayload      *int
}

func addCodecFlags(flags *flag.FlagSet) codecFlagValues {
	return codecFlagValues{
		keyHex:          flags.String("key", "", "hex-encoded PSK of at least 32 bytes"),
		keyFile:         flags.String("key-file", "", "file containing the hex-encoded PSK"),
		minPadding:      flags.Int("padding-min", 0, "minimum encrypted record padding"),
		maxPadding:      flags.Int("padding-max", 0, "maximum encrypted record padding"),
		minCoverPadding: flags.Int("cover-padding-min", 0, "minimum printable cover padding"),
		maxCoverPadding: flags.Int("cover-padding-max", 0, "maximum printable cover padding"),
		maxPayload:      flags.Int("max-payload", 16*1024, "maximum payload bytes per record"),
	}
}

func (values codecFlagValues) config() (enigma.Config, error) {
	if *values.keyHex != "" && *values.keyFile != "" {
		return enigma.Config{}, fmt.Errorf("use only one of -key and -key-file")
	}
	keyText := strings.TrimSpace(*values.keyHex)
	if *values.keyFile != "" {
		encoded, err := os.ReadFile(*values.keyFile)
		if err != nil {
			return enigma.Config{}, fmt.Errorf("read -key-file: %w", err)
		}
		keyText = strings.TrimSpace(string(encoded))
	}
	if keyText == "" {
		return enigma.Config{}, fmt.Errorf("one of -key or -key-file is required")
	}
	key, err := hex.DecodeString(keyText)
	if err != nil {
		return enigma.Config{}, fmt.Errorf("decode -key: %w", err)
	}
	config := enigma.Config{
		Key:             key,
		MinPadding:      *values.minPadding,
		MaxPadding:      *values.maxPadding,
		MinCoverPadding: *values.minCoverPadding,
		MaxCoverPadding: *values.maxCoverPadding,
		MaxPayload:      *values.maxPayload,
	}
	if err := config.Validate(); err != nil {
		return enigma.Config{}, err
	}
	return config, nil
}

type handshakeFlagValues struct {
	timeout      time.Duration
	maxClockSkew time.Duration
}

func addHandshakeFlags(flags *flag.FlagSet) *handshakeFlagValues {
	values := &handshakeFlagValues{}
	flags.DurationVar(&values.timeout, "handshake-timeout", 10*time.Second, "ETPH/1 handshake timeout")
	flags.DurationVar(&values.maxClockSkew, "clock-skew", time.Minute, "accepted client clock skew")
	return values
}

type stringList []string

func (values *stringList) String() string {
	return strings.Join(*values, ",")
}

func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func buildTargetPolicy(values []string) (func(string) bool, error) {
	if len(values) == 0 {
		return nil, nil
	}
	allowed := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "*" {
			return nil, nil
		}
		if err := tunnel.ValidateTargetAddress(value); err != nil {
			return nil, fmt.Errorf("invalid -allow-target %q: %w", value, err)
		}
		allowed[value] = struct{}{}
	}
	return func(address string) bool {
		_, ok := allowed[address]
		return ok
	}, nil
}

func usageError() error {
	return errors.New(usageText)
}

const usageText = `Usage:
  enigma keygen
  enigma server -key-file PATH [-listen :8443] [-allow-target host:port]
  enigma client -key-file PATH -server host:port -target host:port [-listen 127.0.0.1:1080]
  enigma client -key-file PATH -server host:port -socks5 [-listen 127.0.0.1:1080]

The client command supports fixed-target TCP forwarding and no-auth SOCKS5.
It is not an HTTP CONNECT proxy.
`
