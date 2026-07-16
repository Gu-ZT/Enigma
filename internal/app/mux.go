package app

import (
	"context"
	"fmt"
	"net"

	enigmamux "Enigma/internal/mux"
	"Enigma/internal/tunnel"
)

func handleServerMuxConn(ctx context.Context, raw net.Conn, cfg ServerConfig, dialer ContextDialer) error {
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
	session, err := enigmamux.NewSession(conn, cfg.MuxConfig, false)
	if err != nil {
		return fmt.Errorf("mux session: %w", err)
	}
	defer session.Close()
	for {
		stream, err := session.Accept()
		if err != nil {
			return fmt.Errorf("accept mux stream: %w", err)
		}
		go func(stream net.Conn) {
			handler := handleMuxServerStream
			if cfg.UDP {
				handler = handleMuxUDPStream
			}
			if err := handler(ctx, stream, cfg, dialer); err != nil && cfg.Logger != nil {
				cfg.Logger.Printf("mux stream: %v", err)
			}
		}(stream)
	}
}

func handleMuxServerStream(ctx context.Context, stream net.Conn, cfg ServerConfig, dialer ContextDialer) error {
	defer stream.Close()
	targetAddress, err := tunnel.ReadTargetRequest(stream)
	if err != nil {
		return fmt.Errorf("target request: %w", err)
	}
	if cfg.AllowTarget != nil && !cfg.AllowTarget(targetAddress) {
		_ = tunnel.WriteTargetResponse(stream, "target not allowed")
		return fmt.Errorf("target %s is not allowed", targetAddress)
	}
	dialCtx, cancel := context.WithTimeout(ctx, effectiveDialTimeout(cfg.DialTimeout))
	defer cancel()
	target, err := dialer.DialContext(dialCtx, "tcp", targetAddress)
	if err != nil {
		_ = tunnel.WriteTargetResponse(stream, "target unavailable")
		return fmt.Errorf("dial target %s: %w", targetAddress, err)
	}
	defer target.Close()
	if err := tunnel.WriteTargetResponse(stream, ""); err != nil {
		return err
	}
	return relay(stream, target)
}

func serveMuxClient(ctx context.Context, listener net.Listener, cfg ClientConfig, dialer ContextDialer) error {
	dialCtx, cancel := context.WithTimeout(ctx, effectiveDialTimeout(cfg.DialTimeout))
	raw, err := dialer.DialContext(dialCtx, "tcp", cfg.ServerAddress)
	cancel()
	if err != nil {
		return fmt.Errorf("dial server %s: %w", cfg.ServerAddress, err)
	}
	if cfg.WrapConn != nil {
		wrapped, wrapErr := cfg.WrapConn(raw)
		if wrapErr != nil {
			_ = raw.Close()
			return fmt.Errorf("transport wrapper: %w", wrapErr)
		}
		raw = wrapped
	}
	conn, err := tunnel.NewClientConn(raw, cfg.Tunnel)
	if err != nil {
		_ = raw.Close()
		return fmt.Errorf("handshake: %w", err)
	}
	session, err := enigmamux.NewSession(conn, cfg.MuxConfig, true)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("mux session: %w", err)
	}
	defer session.Close()
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
			if err := handleMuxClientConn(ctx, local, cfg, session); err != nil && cfg.Logger != nil {
				cfg.Logger.Printf("mux client connection %s: %v", local.RemoteAddr(), err)
			}
		}()
	}
}

func handleMuxClientConn(ctx context.Context, local net.Conn, cfg ClientConfig, session *enigmamux.Session) error {
	defer local.Close()
	selection, err := selectTarget(local, cfg)
	if err != nil {
		return fmt.Errorf("select target: %w", err)
	}
	if err := tunnel.ValidateTargetAddress(selection.Address); err != nil {
		_ = respondToSelection(selection, err)
		return err
	}
	stream, err := session.Open()
	if err != nil {
		_ = respondToSelection(selection, err)
		return fmt.Errorf("open mux stream: %w", err)
	}
	defer stream.Close()
	if err := tunnel.OpenTarget(stream, selection.Address); err != nil {
		_ = respondToSelection(selection, err)
		return fmt.Errorf("open target %s: %w", selection.Address, err)
	}
	if err := respondToSelection(selection, nil); err != nil {
		return fmt.Errorf("respond to local target request: %w", err)
	}
	return relay(local, stream)
}
