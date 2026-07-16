package enigma

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type coverCodec struct {
	alphabet [64]byte
	decode   [256]int16
	padding  [256]bool
	padBytes []byte
	half     int16
}

func newCoverCodec(alphabet, padding string) (*coverCodec, error) {
	if len(alphabet) != 64 {
		return nil, fmt.Errorf("enigma: CoverAlphabet must contain exactly 64 bytes")
	}
	c := &coverCodec{half: -1}
	for i := range c.decode {
		c.decode[i] = -1
	}
	for i := 0; i < len(alphabet); i++ {
		b := alphabet[i]
		if b < 0x21 || b > 0x7e {
			return nil, fmt.Errorf("enigma: CoverAlphabet contains non-printable ASCII")
		}
		if c.decode[b] >= 0 {
			return nil, fmt.Errorf("enigma: CoverAlphabet contains duplicate byte %q", b)
		}
		c.alphabet[i] = b
		c.decode[b] = int16(i)
	}
	for i := 0; i < len(padding); i++ {
		b := padding[i]
		if b != '\t' && b != '\r' && b != '\n' && (b < 0x20 || b > 0x7e) {
			return nil, fmt.Errorf("enigma: PaddingAlphabet contains unsupported byte")
		}
		if c.decode[b] >= 0 {
			return nil, fmt.Errorf("enigma: padding byte %q overlaps CoverAlphabet", b)
		}
		if !c.padding[b] {
			c.padding[b] = true
			c.padBytes = append(c.padBytes, b)
		}
	}
	return c, nil
}

func (c *coverCodec) encode(raw []byte, minPadding, maxPadding int) ([]byte, error) {
	paddingCount, err := randomRange(minPadding, maxPadding)
	if err != nil {
		return nil, err
	}
	if paddingCount > 0 && len(c.padBytes) == 0 {
		return nil, fmt.Errorf("enigma: cover padding requested without padding alphabet")
	}

	symbolCount := len(raw) * 2
	paddingAt := make([]int, symbolCount+1)
	for i := 0; i < paddingCount; i++ {
		position, err := randomIndex(len(paddingAt))
		if err != nil {
			return nil, err
		}
		paddingAt[position]++
	}

	randomness := make([]byte, len(raw)+paddingCount)
	if _, err := io.ReadFull(rand.Reader, randomness); err != nil {
		return nil, fmt.Errorf("enigma: generate cover randomness: %w", err)
	}
	randomOffset := 0
	out := make([]byte, 0, symbolCount+paddingCount)
	appendPadding := func(slot int) {
		for i := 0; i < paddingAt[slot]; i++ {
			out = append(out, c.padBytes[int(randomness[randomOffset])%len(c.padBytes)])
			randomOffset++
		}
	}

	appendPadding(0)
	for i, b := range raw {
		variants := randomness[randomOffset]
		randomOffset++
		high := int(b >> 4)
		low := int(b & 0x0f)
		out = append(out, c.alphabet[high|int(variants&0x03)<<4])
		appendPadding(i*2 + 1)
		out = append(out, c.alphabet[low|int((variants>>2)&0x03)<<4])
		appendPadding(i*2 + 2)
	}
	return out, nil
}

func (c *coverCodec) readFull(reader *bufio.Reader, destination []byte) (int, error) {
	for i := range destination {
		value, err := c.readByte(reader)
		if err != nil {
			if i > 0 && errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return i, err
		}
		destination[i] = value
	}
	return len(destination), nil
}

func (c *coverCodec) readByte(reader *bufio.Reader) (byte, error) {
	for {
		b, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && c.half >= 0 {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, err
		}
		index := c.decode[b]
		if index >= 0 {
			nibble := index & 0x0f
			if c.half < 0 {
				c.half = nibble
				continue
			}
			value := byte(c.half<<4 | nibble)
			c.half = -1
			return value, nil
		}
		if c.padding[b] {
			continue
		}
		return 0, fmt.Errorf("%w: 0x%02x", ErrUnexpectedCoverByte, b)
	}
}

func randomRange(minValue, maxValue int) (int, error) {
	if minValue == maxValue {
		return minValue, nil
	}
	value, err := randomIndex(maxValue - minValue + 1)
	if err != nil {
		return 0, err
	}
	return minValue + value, nil
}

func randomIndex(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("enigma: invalid random range %d", n)
	}
	if n == 1 {
		return 0, nil
	}
	limit := (uint64(1) << 32) / uint64(n) * uint64(n)
	var buffer [4]byte
	for {
		if _, err := io.ReadFull(rand.Reader, buffer[:]); err != nil {
			return 0, fmt.Errorf("enigma: generate random value: %w", err)
		}
		value := uint64(binary.BigEndian.Uint32(buffer[:]))
		if value < limit {
			return int(value % uint64(n)), nil
		}
	}
}
