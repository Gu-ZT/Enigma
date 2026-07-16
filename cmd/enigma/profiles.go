package main

import "fmt"

type codecProfile struct {
	minPadding      int
	maxPadding      int
	minCoverPadding int
	maxCoverPadding int
	maxPayload      int
}

func codecProfileByName(name string) (codecProfile, error) {
	switch name {
	case "standard":
		return codecProfile{maxPayload: 16 * 1024}, nil
	case "balanced":
		return codecProfile{
			minPadding:      4,
			maxPadding:      64,
			minCoverPadding: 2,
			maxCoverPadding: 32,
			maxPayload:      16 * 1024,
		}, nil
	case "compact":
		return codecProfile{maxPayload: 32 * 1024}, nil
	case "high-padding":
		return codecProfile{
			minPadding:      32,
			maxPadding:      512,
			minCoverPadding: 16,
			maxCoverPadding: 256,
			maxPayload:      8 * 1024,
		}, nil
	default:
		return codecProfile{}, fmt.Errorf("unknown -profile %q; use standard, balanced, compact, or high-padding", name)
	}
}
