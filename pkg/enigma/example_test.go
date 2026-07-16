package enigma_test

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"Enigma/pkg/enigma"
)

func ExampleNewConn() {
	rawClient, rawServer := net.Pipe()
	defer rawClient.Close()
	defer rawServer.Close()

	config := enigma.Config{
		Key:             bytes.Repeat([]byte{0x42}, 32),
		MinPadding:      4,
		MaxPadding:      16,
		MinCoverPadding: 2,
		MaxCoverPadding: 8,
	}
	client, err := enigma.NewConn(rawClient, config)
	if err != nil {
		panic(err)
	}
	server, err := enigma.NewConn(rawServer, config)
	if err != nil {
		panic(err)
	}

	received := make(chan []byte, 1)
	go func() {
		message := make([]byte, len("hello ETP/1"))
		_, readErr := io.ReadFull(server, message)
		if readErr != nil {
			received <- []byte(readErr.Error())
			return
		}
		received <- message
	}()
	if _, err := client.Write([]byte("hello ETP/1")); err != nil {
		panic(err)
	}
	fmt.Println(string(<-received))
	// Output: hello ETP/1
}
