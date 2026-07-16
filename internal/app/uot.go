package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"Enigma/internal/mux"
	"Enigma/internal/tunnel"
	"Enigma/internal/uot"
)

// ServeUDPClient forwards one fixed target through a shared mux session. The
// local UDP socket may receive packets from multiple peers; responses are sent
// to the most recently active local peer for this fixed-target association.
func ServeUDPClient(ctx context.Context, udpConn *net.UDPConn, cfg ClientConfig, dialer ContextDialer) error {
	if udpConn == nil {
		return fmt.Errorf("app: nil UDP connection")
	}
	defer udpConn.Close()
	if !cfg.Mux {
		return fmt.Errorf("app: UDP mode requires mux")
	}
	if cfg.ServerAddress == "" {
		return fmt.Errorf("app: ServerAddress is required")
	}
	if cfg.DialTimeout < 0 {
		return fmt.Errorf("app: DialTimeout must not be negative")
	}
	if err := cfg.Tunnel.ValidateClient(); err != nil {
		return fmt.Errorf("app: invalid client tunnel config: %w", err)
	}
	if cfg.TargetSelector != nil {
		return fmt.Errorf("app: UDP mode requires a fixed target")
	}
	if err := tunnel.ValidateTargetAddress(cfg.TargetAddress); err != nil {
		return fmt.Errorf("app: invalid UDP target: %w", err)
	}
	if dialer == nil {
		dialer = &net.Dialer{}
	}
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
	session, err := mux.NewSession(conn, cfg.MuxConfig, true)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("mux session: %w", err)
	}
	defer session.Close()
	stream, err := session.Open()
	if err != nil {
		return fmt.Errorf("open UDP stream: %w", err)
	}
	defer stream.Close()
	if err := tunnel.OpenTarget(stream, cfg.TargetAddress); err != nil {
		return fmt.Errorf("open UDP target %s: %w", cfg.TargetAddress, err)
	}
	uotConn, err := uot.NewConn(stream, cfg.UoTConfig)
	if err != nil {
		return err
	}
	defer uotConn.Close()
	return relayUDPClient(ctx, udpConn, uotConn, cfg.TargetAddress)
}

func handleMuxUDPStream(ctx context.Context, stream net.Conn, cfg ServerConfig, dialer ContextDialer) error {
	defer stream.Close()
	targetAddress, err := tunnel.ReadTargetRequest(stream)
	if err != nil {
		return fmt.Errorf("UDP target request: %w", err)
	}
	if cfg.AllowTarget != nil && !cfg.AllowTarget(targetAddress) {
		_ = tunnel.WriteTargetResponse(stream, "target not allowed")
		return fmt.Errorf("UDP target %s is not allowed", targetAddress)
	}
	dialCtx, cancel := context.WithTimeout(ctx, effectiveDialTimeout(cfg.DialTimeout))
	defer cancel()
	udpConn, err := dialer.DialContext(dialCtx, "udp", targetAddress)
	if err != nil {
		_ = tunnel.WriteTargetResponse(stream, "target unavailable")
		return fmt.Errorf("dial UDP target %s: %w", targetAddress, err)
	}
	defer udpConn.Close()
	if err := tunnel.WriteTargetResponse(stream, ""); err != nil {
		return err
	}
	uotConn, err := uot.NewConn(stream, cfg.UoTConfig)
	if err != nil {
		return err
	}
	defer uotConn.Close()
	return relayUDPServer(ctx, udpConn, uotConn)
}

func relayUDPClient(ctx context.Context, local *net.UDPConn, remote *uot.Conn, target string) error {
	var peerMu sync.RWMutex
	var peer *net.UDPAddr
	errCh := make(chan error, 2)
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, source, err := local.ReadFromUDP(buffer)
			if err != nil {
				errCh <- err
				return
			}
			peerMu.Lock()
			peer = source
			peerMu.Unlock()
			if _, err := remote.WriteTo(buffer[:n], uot.NewAddr(target)); err != nil {
				errCh <- err
				return
			}
		}
	}()
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, _, err := remote.ReadFrom(buffer)
			if err != nil {
				errCh <- err
				return
			}
			peerMu.RLock()
			destination := peer
			peerMu.RUnlock()
			if destination == nil {
				continue
			}
			if _, err := local.WriteToUDP(buffer[:n], destination); err != nil {
				errCh <- err
				return
			}
		}
	}()
	return waitUDPRelay(ctx, local, remote, errCh)
}

func relayUDPServer(ctx context.Context, remote net.Conn, stream *uot.Conn) error {
	var peerMu sync.RWMutex
	var peer net.Addr
	errCh := make(chan error, 2)
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, source, err := stream.ReadFrom(buffer)
			if err != nil {
				errCh <- err
				return
			}
			peerMu.Lock()
			peer = source
			peerMu.Unlock()
			if _, err := remote.Write(buffer[:n]); err != nil {
				errCh <- err
				return
			}
		}
	}()
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, err := remote.Read(buffer)
			if err != nil {
				errCh <- err
				return
			}
			peerMu.RLock()
			destination := peer
			peerMu.RUnlock()
			if destination == nil {
				continue
			}
			if _, err := stream.WriteTo(buffer[:n], destination); err != nil {
				errCh <- err
				return
			}
		}
	}()
	return waitUDPRelay(ctx, remote, stream, errCh)
}

func waitUDPRelay(ctx context.Context, first io.Closer, second io.Closer, errCh <-chan error) error {
	select {
	case err := <-errCh:
		_ = first.Close()
		_ = second.Close()
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
			return nil
		}
		return err
	case <-ctx.Done():
		_ = first.Close()
		_ = second.Close()
		return nil
	}
}
