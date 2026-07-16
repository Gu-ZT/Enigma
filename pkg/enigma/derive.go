package enigma

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

const derivationPrefix = "enigma/etp/v1/"

func deriveMaster(key []byte) [32]byte {
	return hmacSum(key, []byte(derivationPrefix+"master"))
}

func deriveBytes(key []byte, label string, context []byte, size int) []byte {
	out := make([]byte, 0, size)
	var counter uint32 = 1
	for len(out) < size {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(derivationPrefix + label))
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(context)))
		_, _ = mac.Write(length[:])
		_, _ = mac.Write(context)
		binary.BigEndian.PutUint32(length[:], counter)
		_, _ = mac.Write(length[:])
		out = append(out, mac.Sum(nil)...)
		counter++
	}
	return out[:size]
}

func hmacSum(key, message []byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

type deterministicStream struct {
	key     [32]byte
	counter uint64
	buffer  [32]byte
	offset  int
}

func newDeterministicStream(seed []byte) *deterministicStream {
	return &deterministicStream{key: hmacSum(seed, []byte(derivationPrefix+"table-prng")), offset: 32}
}

func (s *deterministicStream) fill() {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], s.counter)
	s.buffer = hmacSum(s.key[:], counter[:])
	s.counter++
	s.offset = 0
}

func (s *deterministicStream) nextUint32() uint32 {
	if s.offset > len(s.buffer)-4 {
		s.fill()
	}
	value := binary.BigEndian.Uint32(s.buffer[s.offset : s.offset+4])
	s.offset += 4
	return value
}

func (s *deterministicStream) intn(n int) int {
	if n <= 1 {
		return 0
	}
	return int(s.nextUint32() % uint32(n))
}
