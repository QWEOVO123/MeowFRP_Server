package httpapi

import "testing"

func TestNormalizeDPIDetectorsPreservesExplicitEmptySelection(t *testing.T) {
	if got := normalizeDPIDetectors([]string{}); got == nil || len(got) != 0 {
		t.Fatalf("explicit empty selection restored detectors: %#v", got)
	}
	if got := normalizeDPIDetectors(nil); len(got) != 4 {
		t.Fatalf("omitted selection must preserve compatibility default: %#v", got)
	}
	got := normalizeDPIDetectors([]string{" TLS ", "tls", "http", "unknown"})
	if len(got) != 2 || got[0] != "tls" || got[1] != "http" {
		t.Fatalf("detector normalization: %#v", got)
	}
}
