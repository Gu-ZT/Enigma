package tunnel

import (
	"bytes"
	"errors"
	"net"
	"testing"
)

func TestTargetRequestRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	if err := WriteTargetRequest(&wire, "example.com:443"); err != nil {
		t.Fatal(err)
	}
	address, err := ReadTargetRequest(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if address != "example.com:443" {
		t.Fatalf("address = %q", address)
	}
}

func TestTargetIPv6Canonicalization(t *testing.T) {
	var wire bytes.Buffer
	if err := WriteTargetRequest(&wire, "[2001:db8::1]:8443"); err != nil {
		t.Fatal(err)
	}
	address, err := ReadTargetRequest(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if address != "[2001:db8::1]:8443" {
		t.Fatalf("address = %q", address)
	}
}

func TestTargetResponse(t *testing.T) {
	for _, test := range []struct {
		name   string
		reason string
		want   error
	}{
		{name: "success"},
		{name: "rejected", reason: "dial failed", want: ErrTargetRejected},
	} {
		t.Run(test.name, func(t *testing.T) {
			var wire bytes.Buffer
			if err := WriteTargetResponse(&wire, test.reason); err != nil {
				t.Fatal(err)
			}
			err := ReadTargetResponse(&wire)
			if !errors.Is(err, test.want) {
				t.Fatalf("response error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestOpenTargetOverPipe(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serverErr := make(chan error, 1)
	go func() {
		address, err := ReadTargetRequest(server)
		if err == nil && address != "localhost:80" {
			err = errors.New("unexpected target")
		}
		if err == nil {
			err = WriteTargetResponse(server, "")
		}
		serverErr <- err
	}()
	if err := OpenTarget(client, "localhost:80"); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestTargetProtocolRejectsInvalidMessages(t *testing.T) {
	invalidRequests := [][]byte{
		{2, targetCommandConnect, 0, 1, 'x'},
		{targetProtocolVersion, 9, 0, 1, 'x'},
		{targetProtocolVersion, targetCommandConnect, 0, 0},
		{targetProtocolVersion, targetCommandConnect, 0, 3, 'x'},
	}
	for _, wire := range invalidRequests {
		if _, err := ReadTargetRequest(bytes.NewReader(wire)); err == nil {
			t.Fatalf("accepted request %x", wire)
		}
	}
	for _, address := range []string{"", "example.com", ":80", "example.com:0", "example.com:65536"} {
		if err := WriteTargetRequest(&bytes.Buffer{}, address); err == nil {
			t.Fatalf("accepted address %q", address)
		}
	}
}
