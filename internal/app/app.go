// Package app assembles listeners, ETPH/1 tunnels, target negotiation, and TCP
// forwarding into client and server runtimes.
package app

import (
	"context"
	"fmt"
	"net"
	"time"

	"Enigma/internal/tunnel"
)

const defaultDialTimeout = 10 * time.Second

// Logger is the logging surface used by the application runtimes.
type Logger interface {
	Printf(format string, args ...any)
}

// ContextDialer opens outbound TCP connections.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ServerConfig controls accepted tunnel connections and target dialing.
type ServerConfig struct {
	Tunnel tunnel.Config

	DialTimeout time.Duration
	Dialer      ContextDialer
	Logger      Logger

	// AllowTarget may reject a canonical host:port before any outbound dial.
	// A nil function allows every target authenticated by the tunnel PSK.
	AllowTarget func(address string) bool
}

// ClientConfig controls a fixed-target local TCP forwarder.
type ClientConfig struct {
	Tunnel tunnel.Config

	ServerAddress string
	TargetAddress string
	DialTimeout   time.Duration
	Dialer        ContextDialer
	Logger        Logger
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
			if err := handleServerConn(ctx, raw, cfg, dialer); err != nil && cfg.Logger != nil {
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
	if err := tunnel.ValidateTargetAddress(cfg.TargetAddress); err != nil {
		return fmt.Errorf("app: invalid TargetAddress: %w", err)
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
	dialCtx, cancel := context.WithTimeout(ctx, effectiveDialTimeout(cfg.DialTimeout))
	raw, err := dialer.DialContext(dialCtx, "tcp", cfg.ServerAddress)
	cancel()
	if err != nil {
		return fmt.Errorf("dial server %s: %w", cfg.ServerAddress, err)
	}
	defer raw.Close()
	conn, err := tunnel.NewClientConn(raw, cfg.Tunnel)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	if err := tunnel.OpenTarget(conn, cfg.TargetAddress); err != nil {
		return fmt.Errorf("open target %s: %w", cfg.TargetAddress, err)
	}
	return relay(local, conn)
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
