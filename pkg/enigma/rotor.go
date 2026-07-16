package enigma

import "encoding/binary"

const rotorCount = 3

type rotor struct {
	forward [256]byte
	inverse [256]byte
	notch   byte
}

type rotorSet struct {
	rotors    [rotorCount]rotor
	plugboard [256]byte
	reflector [256]byte
	stateKey  [32]byte
}

type machine struct {
	set       *rotorSet
	positions [rotorCount]byte
	rings     [rotorCount]byte
}

func newRotorSet(seed []byte) rotorSet {
	stream := newDeterministicStream(seed)
	var set rotorSet
	copy(set.stateKey[:], deriveBytes(seed, "rotor-state-key", nil, len(set.stateKey)))

	for i := range set.rotors {
		permutation := shuffledAlphabet(stream)
		set.rotors[i].forward = permutation
		for input, output := range permutation {
			set.rotors[i].inverse[output] = byte(input)
		}
		set.rotors[i].notch = byte(stream.intn(256))
	}
	set.plugboard = pairedInvolution(stream)
	set.reflector = pairedInvolution(stream)
	return set
}

func shuffledAlphabet(stream *deterministicStream) [256]byte {
	var values [256]byte
	for i := range values {
		values[i] = byte(i)
	}
	for i := len(values) - 1; i > 0; i-- {
		j := stream.intn(i + 1)
		values[i], values[j] = values[j], values[i]
	}
	return values
}

func pairedInvolution(stream *deterministicStream) [256]byte {
	values := shuffledAlphabet(stream)
	var mapping [256]byte
	for i := 0; i < len(values); i += 2 {
		a, b := values[i], values[i+1]
		mapping[a] = b
		mapping[b] = a
	}
	return mapping
}

func (s *rotorSet) machineFor(sequence uint64) machine {
	var context [8]byte
	binary.BigEndian.PutUint64(context[:], sequence)
	state := deriveBytes(s.stateKey[:], "frame-rotor-state", context[:], rotorCount*2)
	var result machine
	result.set = s
	copy(result.positions[:], state[:rotorCount])
	copy(result.rings[:], state[rotorCount:])
	return result
}

func (m *machine) transform(data []byte) {
	for i := range data {
		data[i] = m.transformByte(data[i])
	}
}

func (m *machine) transformByte(value byte) byte {
	m.step()
	value = m.set.plugboard[value]
	for i := 0; i < rotorCount; i++ {
		value = rotorForward(m.set.rotors[i], value, m.positions[i], m.rings[i])
	}
	value = m.set.reflector[value]
	for i := rotorCount - 1; i >= 0; i-- {
		value = rotorReverse(m.set.rotors[i], value, m.positions[i], m.rings[i])
	}
	return m.set.plugboard[value]
}

func (m *machine) step() {
	m.positions[0]++
	if m.positions[0] != m.set.rotors[0].notch {
		return
	}
	m.positions[1]++
	if m.positions[1] == m.set.rotors[1].notch {
		m.positions[2]++
	}
}

func rotorForward(r rotor, value, position, ring byte) byte {
	shifted := byte(int(value) + int(position) - int(ring))
	mapped := r.forward[shifted]
	return byte(int(mapped) - int(position) + int(ring))
}

func rotorReverse(r rotor, value, position, ring byte) byte {
	shifted := byte(int(value) + int(position) - int(ring))
	mapped := r.inverse[shifted]
	return byte(int(mapped) - int(position) + int(ring))
}
