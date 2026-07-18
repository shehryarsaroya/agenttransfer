package server

const maxStorageBytes = int64(^uint64(0) >> 1)

// addStorageBytes accepts only non-negative byte counts and refuses int64
// overflow. Runner observations and database values cross trust boundaries;
// wrapping a huge value negative would otherwise turn an over-quota workload
// into an apparently tiny one.
func addStorageBytes(a, b int64) (int64, bool) {
	if a < 0 || b < 0 || a > maxStorageBytes-b {
		return 0, false
	}
	return a + b, true
}

func storageAdditionFits(used, additional, quota int64) bool {
	total, ok := addStorageBytes(used, additional)
	return ok && quota >= 0 && total <= quota
}
