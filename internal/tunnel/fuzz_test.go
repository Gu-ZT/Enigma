package tunnel

import (
	"bytes"
	"testing"
	"time"
)

func FuzzOpenHandshakePacket(f *testing.F) {
	f.Add([]byte("handshake packet"), []byte("aad"))
	f.Add(bytes.Repeat([]byte{0}, clientPacketSize), clientAAD())
	f.Fuzz(func(t *testing.T, packet, aad []byte) {
		if len(packet) > 1024 || len(aad) > 1024 {
			t.Skip()
		}
		psk := bytes.Repeat([]byte{0x42}, 32)
		_, _ = openHandshakePacket(psk, aad, packet)
	})
}

func FuzzAcceptClientHello(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0}, clientPacketSize))
	f.Add([]byte("short"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1024 {
			t.Skip()
		}
		var packet [clientPacketSize]byte
		copy(packet[:], input)
		guard, err := NewReplayGuard(4, 2*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		psk := bytes.Repeat([]byte{0x24}, 32)
		_, _ = acceptClientHello(psk, packet, time.Unix(10_000, 0), time.Minute, guard)
	})
}
