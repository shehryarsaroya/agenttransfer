package server

import "testing"

func TestStorageAdditionFitsWithoutOverflow(t *testing.T) {
	for _, tt := range []struct {
		name             string
		used, added, max int64
		want             bool
	}{
		{name: "exact boundary", used: 7, added: 3, max: 10, want: true},
		{name: "ordinary overflow", used: 7, added: 4, max: 10, want: false},
		{name: "int64 boundary", used: maxStorageBytes - 1, added: 1, max: maxStorageBytes, want: true},
		{name: "int64 wrap", used: maxStorageBytes - 1, added: 2, max: maxStorageBytes, want: false},
		{name: "negative observation", used: 1, added: -1, max: 10, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := storageAdditionFits(tt.used, tt.added, tt.max); got != tt.want {
				t.Fatalf("storageAdditionFits(%d,%d,%d)=%v, want %v", tt.used, tt.added, tt.max, got, tt.want)
			}
		})
	}
}
