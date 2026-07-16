package enigma

import (
	"bytes"
	"testing"
)

func TestRotorTransformIsInvolutive(t *testing.T) {
	seed := bytes.Repeat([]byte{0x5a}, 32)
	set := newRotorSet(seed)
	original := make([]byte, 256*4)
	for i := range original {
		original[i] = byte(i)
	}

	transformed := append([]byte(nil), original...)
	encoder := set.machineFor(17)
	encoder.transform(transformed)
	if bytes.Equal(transformed, original) {
		t.Fatal("rotor transform did not change input")
	}

	decoder := set.machineFor(17)
	decoder.transform(transformed)
	if !bytes.Equal(transformed, original) {
		t.Fatal("second rotor transform did not recover input")
	}
}

func TestRotorStateDependsOnSeedAndSequence(t *testing.T) {
	input := bytes.Repeat([]byte("etp-state"), 64)
	transform := func(seedByte byte, sequence uint64) []byte {
		set := newRotorSet(bytes.Repeat([]byte{seedByte}, 32))
		out := append([]byte(nil), input...)
		machine := set.machineFor(sequence)
		machine.transform(out)
		return out
	}

	base := transform(1, 0)
	if bytes.Equal(base, transform(2, 0)) {
		t.Fatal("different seeds produced the same transform")
	}
	if bytes.Equal(base, transform(1, 1)) {
		t.Fatal("different sequences produced the same transform")
	}
}

func TestDerivedMappingsArePermutationsAndInvolutions(t *testing.T) {
	set := newRotorSet([]byte("deterministic rotor seed"))
	for rotorIndex, rotor := range set.rotors {
		seen := [256]bool{}
		for input, output := range rotor.forward {
			if seen[output] {
				t.Fatalf("rotor %d repeats output %d", rotorIndex, output)
			}
			seen[output] = true
			if rotor.inverse[output] != byte(input) {
				t.Fatalf("rotor %d inverse mismatch at %d", rotorIndex, input)
			}
		}
	}
	for i := 0; i < 256; i++ {
		value := byte(i)
		if set.plugboard[set.plugboard[value]] != value {
			t.Fatalf("plugboard is not involutive at %d", i)
		}
		if set.reflector[set.reflector[value]] != value || set.reflector[value] == value {
			t.Fatalf("reflector is invalid at %d", i)
		}
	}
}
