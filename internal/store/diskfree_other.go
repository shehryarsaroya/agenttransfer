//go:build !(linux || darwin)

package store

import "errors"

// VolumeStats is unsupported on this platform; the disk guard stays disabled.
func VolumeStats(path string) (free, total int64, err error) {
	return 0, 0, errors.New("volume stats unsupported on this platform")
}
