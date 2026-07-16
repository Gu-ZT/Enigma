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
	muxEnabled := flags.Bool("mux", false, "reuse one authenticated connection for multiple streams")
	udpEnabled := flags.Bool("udp", false, "serve UoT UDP streams; requires -mux")
	dialTimeout := flags.Duration("dial-timeout", 10*time.Second, "target dial timeout")
	replayCapacity := flags.Int("replay-capacity", 65536, "maximum live client nonces")
	replayTTL := flags.Duration("replay-ttl", 2*time.Minute, "client nonce retention")
	var allowedTargets stringList
	flags.Var(&allowedTargets, "allow-target", "allowed host:port, *.domain:port, or CIDR:port; repeatable, empty allows all")
	codecFlags := addCodecFlags(flags)
	handshakeFlags := addHandshakeFlags(flags)
	transportFlags := addServerTransportFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("server does not accept positional arguments")
	}
	if *udpEnabled && !*muxEnabled {
		return fmt.Errorf("-udp requires -mux")
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
	wrapConn, err := transportFlags.wrapper(handshakeFlags.timeout)
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
		Mux:         *muxEnabled,
		UDP:         *udpEnabled,
		DialTimeout: *dialTimeout,
		Logger:      logger,
		AllowTarget: allowTarget,
		WrapConn:    wrapConn,
	})
}

func runClient(ctx context.Context, args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listenAddress := flags.String("listen", "127.0.0.1:1080", "local TCP or UDP listen address")
	muxEnabled := flags.Bool("mux", false, "reuse one authenticated connection for multiple local connections")
	udpEnabled := flags.Bool("udp", false, "listen on UDP and forward a fixed target; requires -mux")
	serverAddress := flags.String("server", "", "ETPH/1 server host:port")
	targetAddress := flags.String("target", "", "fixed target host:port")
	socks5 := flags.Bool("socks5", false, "serve a local no-auth SOCKS5 listener instead of a fixed target")
	httpConnect := flags.Bool("http-connect", false, "serve a local HTTP CONNECT listener instead of a fixed target")
	localHandshakeTimeout := 10 * time.Second
	flags.DurationVar(&localHandshakeTimeout, "local-handshake-timeout", localHandshakeTimeout, "local SOCKS5/HTTP handshake timeout")
	flags.DurationVar(&localHandshakeTimeout, "socks5-timeout", localHandshakeTimeout, "deprecated alias for -local-handshake-timeout")
	flags.DurationVar(&localHandshakeTimeout, "http-timeout", localHandshakeTimeout, "deprecated alias for -local-handshake-timeout")
	dialTimeout := flags.Duration("dial-timeout", 10*time.Second, "server dial timeout")
	codecFlags := addCodecFlags(flags)
	handshakeFlags := addHandshakeFlags(flags)
	transportFlags := addClientTransportFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("client does not accept positional arguments")
	}
	if *serverAddress == "" {
		return fmt.Errorf("client -server is required")
	}
	if *socks5 && *httpConnect {
		return fmt.Errorf("-socks5 and -http-connect are mutually exclusive")
	}
	if *udpEnabled && (!*muxEnabled || *socks5 || *httpConnect) {
		return fmt.Errorf("-udp requires -mux and cannot be combined with -socks5 or -http-connect")
	}
	if *socks5 || *httpConnect {
		if *targetAddress != "" {
			return fmt.Errorf("-target cannot be used with protocol-selected local modes")
		}
		if localHandshakeTimeout < 0 {
			return fmt.Errorf("local handshake timeout must not be negative")
		}
	} else if err := tunnel.ValidateTargetAddress(*targetAddress); err != nil {
		return fmt.Errorf("invalid -target: %w", err)
	}
	if *udpEnabled && *targetAddress == "" {
		return fmt.Errorf("-udp requires -target")
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
	wrapConn, err := transportFlags.wrapper(*serverAddress, handshakeFlags.timeout)
	if err != nil {
		return err
	}
	if *udpEnabled {
		udpAddress, err := net.ResolveUDPAddr("udp", *listenAddress)
		if err != nil {
			return fmt.Errorf("resolve UDP listen address: %w", err)
		}
		udpListener, err := net.ListenUDP("udp", udpAddress)
		if err != nil {
			return fmt.Errorf("listen UDP %s: %w", *listenAddress, err)
		}
		logger := log.New(stderr, "enigma-client: ", log.LstdFlags)
		logger.Printf("UDP listening on %s through %s to %s", udpListener.LocalAddr(), *serverAddress, *targetAddress)
		return app.ServeUDPClient(ctx, udpListener, app.ClientConfig{
			Tunnel:        tunnelConfig,
			Mux:           true,
			UDP:           true,
			ServerAddress: *serverAddress,
			TargetAddress: *targetAddress,
			DialTimeout:   *dialTimeout,
			Logger:        logger,
			WrapConn:      wrapConn,
		}, nil)
	}
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *listenAddress, err)
	}
	logger := log.New(stderr, "enigma-client: ", log.LstdFlags)
	if *socks5 {
		logger.Printf("SOCKS5 listening on %s through %s", listener.Addr(), *serverAddress)
	} else if *httpConnect {
		logger.Printf("HTTP CONNECT listening on %s through %s", listener.Addr(), *serverAddress)
	} else {
		logger.Printf("listening on %s, forwarding to %s through %s", listener.Addr(), *targetAddress, *serverAddress)
	}
	return app.ServeClient(ctx, listener, app.ClientConfig{
		Tunnel:                tunnelConfig,
		Mux:                   *muxEnabled,
		ServerAddress:         *serverAddress,
		TargetAddress:         *targetAddress,
		TargetSelector:        selectTargetSelector(*socks5, *httpConnect),
		LocalHandshakeTimeout: localHandshakeTimeout,
		DialTimeout:           *dialTimeout,
		Logger:                logger,
		WrapConn:              wrapConn,
	})
}

func selectTargetSelector(socks5, httpConnect bool) app.TargetSelector {
	if socks5 {
		return app.SOCKS5Selector
	}
	if httpConnect {
		return app.HTTPConnectSelector
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

func usageError() error {
	return errors.New(usageText)
}

const usageText = `Usage:
  enigma keygen
  enigma server -key-file PATH [-listen :8443] [-mux] [-allow-target rule]
  enigma client -key-file PATH -server host:port [-mux] -target host:port [-listen 127.0.0.1:1080]
  enigma client -key-file PATH -server host:port -socks5 [-listen 127.0.0.1:1080]
  enigma client -key-file PATH -server host:port -mux -udp -target host:port [-listen 127.0.0.1:1080]
  enigma client -key-file PATH -server host:port -http-connect [-listen 127.0.0.1:1080]

The client command supports fixed-target TCP forwarding, no-auth SOCKS5, and HTTP CONNECT.
`
