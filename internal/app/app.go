// Package app assembles listeners, ETPH/1 tunnels, target negotiation, and TCP
// forwarding into client and server runtimes.
package app

import (
	"context"
	"fmt"
	"net"
	"time"

	enigmamux "Enigma/internal/mux"
	"Enigma/internal/tunnel"
	"Enigma/internal/uot"
)

const defaultDialTimeout = 10 * time.Second

// Logger is the logging surface used by the application runtimes.
type Logger interface {
	Printf(format string, args ...any)
}

// ContextDialer opens outbound TCP or UDP connections.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ConnWrapper optionally upgrades a raw connection before ETPH/1 starts. It
// is used for transport profiles such as TLS or an HTTP prelude.
type ConnWrapper func(net.Conn) (net.Conn, error)

// TargetSelection is the result of a local target protocol handshake.
// Respond is called exactly once after the remote target succeeds or fails.
type TargetSelection struct {
	Address string
	Respond func(error) error
}

// TargetSelector extracts one canonical target from a local connection.
type TargetSelector func(net.Conn) (TargetSelection, error)

// ServerConfig controls accepted tunnel connections and target dialing.
type ServerConfig struct {
	Tunnel    tunnel.Config
	Mux       bool
	MuxConfig enigmamux.Config
	UDP       bool
	UoTConfig uot.Config

	DialTimeout time.Duration
	Dialer      ContextDialer
	Logger      Logger
	WrapConn    ConnWrapper

	// AllowTarget may reject a canonical host:port before any outbound dial.
	// A nil function allows every target authenticated by the tunnel PSK.
	AllowTarget func(address string) bool
}

// ClientConfig controls a fixed-target or protocol-selected local TCP forwarder.
type ClientConfig struct {
	Tunnel    tunnel.Config
	Mux       bool
	MuxConfig enigmamux.Config
	UDP       bool
	UoTConfig uot.Config

	ServerAddress         string
	TargetAddress         string
	TargetSelector        TargetSelector
	LocalHandshakeTimeout time.Duration
	DialTimeout           time.Duration
	Dialer                ContextDialer
	Logger                Logger
	WrapConn              ConnWrapper
}

// ServeServer accepts ETPH/1 connections until ctx is canceled or listener
// fails. Canceling ctx closes listener; established relays finish independently.
func ServeServer(ctx context.Context, listener net.Listener, cfg ServerConfig) error {
	if listener == nil {
		return fmt.Errorf("app: nil server listener")
	}
	if cfg.DialTimeout < 0 {
		return fmt.Errorf("app: DialTimeout must not be negative")
	}
	if cfg.UDP && !cfg.Mux {
		return fmt.Errorf("app: UDP mode requires mux")
	}
	if err := cfg.Tunnel.ValidateServer(); err != nil {
		return fmt.Errorf("app: invalid server tunnel config: %w", err)
	}
	dialer := cfg.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	stop := closeListenerOnCancel(ctx, listener)
	defer close(stop)
	for {
		raw, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("app: accept tunnel: %w", err)
		}
		go func() {
			handler := handleServerConn
			if cfg.Mux {
				handler = handleServerMuxConn
			}
			if err := handler(ctx, raw, cfg, dialer); err != nil && cfg.Logger != nil {
				cfg.Logger.Printf("server connection %s: %v", raw.RemoteAddr(), err)
			}
		}()
	}
}

// ServeClient accepts local TCP connections and forwards each one to the fixed
// target through a new authenticated tunnel.
func ServeClient(ctx context.Context, listener net.Listener, cfg ClientConfig) error {
	if listener == nil {
		return fmt.Errorf("app: nil client listener")
	}
	if cfg.ServerAddress == "" {
		return fmt.Errorf("app: ServerAddress is required")
	}
	if cfg.TargetSelector == nil {
		if err := tunnel.ValidateTargetAddress(cfg.TargetAddress); err != nil {
			return fmt.Errorf("app: invalid TargetAddress: %w", err)
		}
	} else if cfg.TargetAddress != "" {
		return fmt.Errorf("app: TargetAddress must be empty when TargetSelector is set")
	}
	if cfg.LocalHandshakeTimeout < 0 {
		return fmt.Errorf("app: LocalHandshakeTimeout must not be negative")
	}
	if cfg.DialTimeout < 0 {
		return fmt.Errorf("app: DialTimeout must not be negative")
	}
	if err := cfg.Tunnel.ValidateClient(); err != nil {
		return fmt.Errorf("app: invalid client tunnel config: %w", err)
	}
	dialer := cfg.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	if cfg.Mux {
		return serveMuxClient(ctx, listener, cfg, dialer)
	}
	stop := closeListenerOnCancel(ctx, listener)
	defer close(stop)
	for {
		local, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("app: accept local connection: %w", err)
		}
		go func() {
			if err := handleClientConn(ctx, local, cfg, dialer); err != nil && cfg.Logger != nil {
				cfg.Logger.Printf("client connection %s: %v", local.RemoteAddr(), err)
			}
		}()
	}
}

func handleServerConn(ctx context.Context, raw net.Conn, cfg ServerConfig, dialer ContextDialer) error {
	defer raw.Close()
	if cfg.WrapConn != nil {
		wrapped, err := cfg.WrapConn(raw)
		if err != nil {
			return fmt.Errorf("transport wrapper: %w", err)
		}
		raw = wrapped
		defer raw.Close()
	}
	conn, err := tunnel.NewServerConn(raw, cfg.Tunnel)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	targetAddress, err := tunnel.ReadTargetRequest(conn)
	if err != nil {
		return fmt.Errorf("target request: %w", err)
	}
	if cfg.AllowTarget != nil && !cfg.AllowTarget(targetAddress) {
		_ = tunnel.WriteTargetResponse(conn, "target not allowed")
		return fmt.Errorf("target %s is not allowed", targetAddress)
	}
	dialCtx, cancel := context.WithTimeout(ctx, effectiveDialTimeout(cfg.DialTimeout))
	defer cancel()
	target, err := dialer.DialContext(dialCtx, "tcp", targetAddress)
	if err != nil {
		_ = tunnel.WriteTargetResponse(conn, "target unavailable")
		return fmt.Errorf("dial target %s: %w", targetAddress, err)
	}
	defer target.Close()
	if err := tunnel.WriteTargetResponse(conn, ""); err != nil {
		return err
	}
	return relay(conn, target)
}

func handleClientConn(ctx context.Context, local net.Conn, cfg ClientConfig, dialer ContextDialer) error {
	defer local.Close()
	selection, err := selectTarget(local, cfg)
	if err != nil {
		return fmt.Errorf("select target: %w", err)
	}
	if err := tunnel.ValidateTargetAddress(selection.Address); err != nil {
		_ = respondToSelection(selection, err)
		return err
	}
	dialCtx, cancel := context.WithTimeout(ctx, effectiveDialTimeout(cfg.DialTimeout))
	raw, err := dialer.DialContext(dialCtx, "tcp", cfg.ServerAddress)
	cancel()
	if err != nil {
		_ = respondToSelection(selection, err)
		return fmt.Errorf("dial server %s: %w", cfg.ServerAddress, err)
	}
	defer raw.Close()
	if cfg.WrapConn != nil {
		wrapped, err := cfg.WrapConn(raw)
		if err != nil {
			_ = respondToSelection(selection, err)
			return fmt.Errorf("transport wrapper: %w", err)
		}
		raw = wrapped
		defer raw.Close()
	}
	conn, err := tunnel.NewClientConn(raw, cfg.Tunnel)
	if err != nil {
		_ = respondToSelection(selection, err)
		return fmt.Errorf("handshake: %w", err)
	}
	if err := tunnel.OpenTarget(conn, selection.Address); err != nil {
		_ = respondToSelection(selection, err)
		return fmt.Errorf("open target %s: %w", selection.Address, err)
	}
	if err := respondToSelection(selection, nil); err != nil {
		return fmt.Errorf("respond to local target request: %w", err)
	}
	return relay(local, conn)
}

func selectTarget(local net.Conn, cfg ClientConfig) (TargetSelection, error) {
	if cfg.TargetSelector == nil {
		return TargetSelection{Address: cfg.TargetAddress}, nil
	}
	timeout := cfg.LocalHandshakeTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if timeout > 0 {
		if err := local.SetDeadline(time.Now().Add(timeout)); err != nil {
			return TargetSelection{}, fmt.Errorf("set local handshake deadline: %w", err)
		}
		defer local.SetDeadline(time.Time{})
	}
	return cfg.TargetSelector(local)
}

func respondToSelection(selection TargetSelection, err error) error {
	if selection.Respond == nil {
		return nil
	}
	return selection.Respond(err)
}

func effectiveDialTimeout(value time.Duration) time.Duration {
	if value == 0 {
		return defaultDialTimeout
	}
	return value
}

func closeListenerOnCancel(ctx context.Context, listener net.Listener) chan struct{} {
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stop:
		}
	}()
	return stop
}
