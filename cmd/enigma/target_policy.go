package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"Enigma/internal/tunnel"
)

type targetRule interface {
	match(string) bool
}

type exactTargetRule struct{ address string }

func (r exactTargetRule) match(address string) bool { return address == r.address }

type hostPortRule struct {
	host          string
	port          int
	anyPort       bool
	subdomainOnly bool
}

func (r hostPortRule) match(address string) bool {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return false
	}
	if !r.anyPort && port != r.port {
		return false
	}
	host = strings.ToLower(host)
	if r.subdomainOnly {
		return host != r.host && strings.HasSuffix(host, "."+r.host)
	}
	return host == r.host
}

type cidrTargetRule struct {
	network *net.IPNet
	port    int
	anyPort bool
}

func (r cidrTargetRule) match(address string) bool {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if !r.anyPort {
		port, err := strconv.Atoi(portText)
		if err != nil || port != r.port {
			return false
		}
	}
	return r.network.Contains(net.ParseIP(host))
}

func parseTargetRule(value string) (targetRule, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return nil, fmt.Errorf("target rule must be host:port, wildcard, or CIDR: %w", err)
	}
	port, anyPort, err := parseRulePort(portText)
	if err != nil {
		return nil, err
	}
	if strings.Contains(host, "/") {
		_, network, err := net.ParseCIDR(host)
		if err != nil {
			return nil, fmt.Errorf("invalid target CIDR %q: %w", host, err)
		}
		return cidrTargetRule{network: network, port: port, anyPort: anyPort}, nil
	}
	if strings.HasPrefix(host, "*.") {
		suffix := strings.TrimPrefix(strings.ToLower(host), "*.")
		if suffix == "" || strings.ContainsAny(suffix, "*/") {
			return nil, fmt.Errorf("invalid wildcard target host %q", host)
		}
		return hostPortRule{host: suffix, port: port, anyPort: anyPort, subdomainOnly: true}, nil
	}
	if strings.Contains(host, "*") {
		return nil, fmt.Errorf("wildcard is only supported as the *.domain prefix")
	}
	if anyPort {
		if err := tunnel.ValidateTargetAddress(net.JoinHostPort(host, "1")); err != nil {
			return nil, fmt.Errorf("invalid target host %q: %w", host, err)
		}
		return hostPortRule{host: strings.ToLower(host), anyPort: true}, nil
	}
	if err := tunnel.ValidateTargetAddress(value); err != nil {
		return nil, err
	}
	return exactTargetRule{address: value}, nil
}

func parseRulePort(value string) (port int, any bool, err error) {
	if value == "*" {
		return 0, true, nil
	}
	port, err = strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, false, fmt.Errorf("invalid target rule port %q", value)
	}
	return port, false, nil
}

func buildTargetPolicy(values []string) (func(string) bool, error) {
	if len(values) == 0 {
		return nil, nil
	}
	rules := make([]targetRule, 0, len(values))
	for _, value := range values {
		if value == "*" {
			return nil, nil
		}
		rule, err := parseTargetRule(value)
		if err != nil {
			return nil, fmt.Errorf("invalid -allow-target %q: %w", value, err)
		}
		rules = append(rules, rule)
	}
	return func(address string) bool {
		for _, rule := range rules {
			if rule.match(address) {
				return true
			}
		}
		return false
	}, nil
}
