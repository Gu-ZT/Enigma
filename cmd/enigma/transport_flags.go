package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"Enigma/internal/app"
	"Enigma/internal/transport"
)

type serverTransportFlags struct {
	tlsEnabled  *bool
	tlsCertFile *string
	tlsKeyFile  *string
	httpEnabled *bool
	httpHost    *string
	httpPath    *string
}

func addServerTransportFlags(flags *flag.FlagSet) serverTransportFlags {
	return serverTransportFlags{
		tlsEnabled:  flags.Bool("tls", false, "wrap the public connection with TLS"),
		tlsCertFile: flags.String("tls-cert", "", "TLS server certificate PEM"),
		tlsKeyFile:  flags.String("tls-key", "", "TLS server private key PEM"),
		httpEnabled: flags.Bool("http-camouflage", false, "expect an HTTP/1.1 camouflage prelude"),
		httpHost:    flags.String("http-host", "", "expected HTTP camouflage Host header"),
		httpPath:    flags.String("http-path", "/", "expected HTTP camouflage request path"),
	}
}

type clientTransportFlags struct {
	tlsEnabled    *bool
	tlsCAFile     *string
	tlsServerName *string
	tlsInsecure   *bool
	httpEnabled   *bool
	httpHost      *string
	httpPath      *string
}

func addClientTransportFlags(flags *flag.FlagSet) clientTransportFlags {
	return clientTransportFlags{
		tlsEnabled:    flags.Bool("tls", false, "wrap the server connection with TLS"),
		tlsCAFile:     flags.String("tls-ca-file", "", "PEM CA bundle for TLS server verification"),
		tlsServerName: flags.String("tls-server-name", "", "TLS server name; defaults to -server host"),
		tlsInsecure:   flags.Bool("tls-insecure-skip-verify", false, "disable TLS certificate verification (unsafe)"),
		httpEnabled:   flags.Bool("http-camouflage", false, "send an HTTP/1.1 camouflage prelude"),
		httpHost:      flags.String("http-host", "", "HTTP camouflage Host header; defaults to TLS/server host"),
		httpPath:      flags.String("http-path", "/", "HTTP camouflage request path"),
	}
}

func (values serverTransportFlags) wrapper(timeout time.Duration) (app.ConnWrapper, error) {
	if !*values.tlsEnabled && (*values.tlsCertFile != "" || *values.tlsKeyFile != "") {
		return nil, fmt.Errorf("-tls-cert and -tls-key require -tls")
	}
	if *values.tlsEnabled && (*values.tlsCertFile == "" || *values.tlsKeyFile == "") {
		return nil, fmt.Errorf("-tls requires both -tls-cert and -tls-key")
	}
	var certificate tls.Certificate
	if *values.tlsEnabled {
		var err error
		certificate, err = tls.LoadX509KeyPair(*values.tlsCertFile, *values.tlsKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS certificate: %w", err)
		}
	}
	if !*values.tlsEnabled && !*values.httpEnabled {
		return nil, nil
	}
	httpConfig := transport.HTTPConfig{Host: *values.httpHost, Path: *values.httpPath}
	return func(raw net.Conn) (net.Conn, error) {
		conn := raw
		deadline := effectiveTransportTimeout(timeout)
		if deadline > 0 {
			if err := conn.SetDeadline(time.Now().Add(deadline)); err != nil {
				return nil, err
			}
			defer conn.SetDeadline(time.Time{})
		}
		var err error
		if *values.tlsEnabled {
			conn, err = transport.ServerTLS(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}, deadline)
			if err != nil {
				return nil, err
			}
		}
		if *values.httpEnabled {
			if deadline > 0 {
				if err := conn.SetDeadline(time.Now().Add(deadline)); err != nil {
					return nil, err
				}
			}
			conn, err = transport.ServerHTTP(conn, httpConfig)
			if err != nil {
				return nil, err
			}
		}
		return conn, nil
	}, nil
}

func (values clientTransportFlags) wrapper(serverAddress string, timeout time.Duration) (app.ConnWrapper, error) {
	if !*values.tlsEnabled && (*values.tlsCAFile != "" || *values.tlsServerName != "" || *values.tlsInsecure) {
		return nil, fmt.Errorf("TLS client options require -tls")
	}
	if !*values.tlsEnabled && !*values.httpEnabled {
		return nil, nil
	}
	serverName := *values.tlsServerName
	if serverName == "" {
		serverName = serverHost(serverAddress)
	}
	if serverName == "" && *values.tlsEnabled && !*values.tlsInsecure {
		return nil, fmt.Errorf("-tls-server-name is required when -server has no host")
	}
	roots, err := loadTLSRoots(*values.tlsCAFile)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		ServerName:         serverName,
		RootCAs:            roots,
		InsecureSkipVerify: *values.tlsInsecure, // explicit CLI opt-in
		MinVersion:         tls.VersionTLS13,
	}
	httpHost := *values.httpHost
	if httpHost == "" {
		httpHost = serverName
	}
	httpConfig := transport.HTTPConfig{Host: httpHost, Path: *values.httpPath}
	return func(raw net.Conn) (net.Conn, error) {
		conn := raw
		deadline := effectiveTransportTimeout(timeout)
		if deadline > 0 {
			if err := conn.SetDeadline(time.Now().Add(deadline)); err != nil {
				return nil, err
			}
			defer conn.SetDeadline(time.Time{})
		}
		if *values.tlsEnabled {
			conn, err = transport.ClientTLS(conn, tlsConfig, deadline)
			if err != nil {
				return nil, err
			}
		}
		if *values.httpEnabled {
			if deadline > 0 {
				if err := conn.SetDeadline(time.Now().Add(deadline)); err != nil {
					return nil, err
				}
			}
			conn, err = transport.ClientHTTP(conn, httpConfig)
			if err != nil {
				return nil, err
			}
		}
		return conn, nil
	}, nil
}

func effectiveTransportTimeout(timeout time.Duration) time.Duration {
	if timeout == 0 {
		return 10 * time.Second
	}
	return timeout
}

func serverHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(address, "[]")
}

func loadTLSRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read -tls-ca-file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("read -tls-ca-file: no certificates found")
	}
	return pool, nil
}
