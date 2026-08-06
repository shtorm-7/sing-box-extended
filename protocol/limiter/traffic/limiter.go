package traffic

type TrafficLimiter interface {
	Reserve(n uint64) (uint64, error)
	Commit(reserved uint64, n uint64)
}
