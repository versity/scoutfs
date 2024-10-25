package restore

import "testing"

func TestNewWriters(t *testing.T) {
	_, _, err := NewWriters("/tmp", 2)
	if err != nil {
		t.Fatalf("failed to create master writer: %v", err)
	}
}
