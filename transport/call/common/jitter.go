package common

import (
	"math/rand/v2"
	"time"
)

const backoffJitterFloorDivisor = 4

func BackoffWithJitter(attempt int, initialDelay, maxDelay time.Duration) time.Duration {
	if initialDelay <= 0 {
		return 0
	}
	if maxDelay < initialDelay {
		maxDelay = initialDelay
	}
	if attempt < 0 {
		attempt = 0
	}
	ceiling := maxDelay
	if shifted := initialDelay << uint(attempt); shifted > 0 && shifted < maxDelay {
		ceiling = shifted
	}
	floor := ceiling / backoffJitterFloorDivisor
	return floor + time.Duration(rand.Int64N(int64(ceiling-floor)+1))
}

func DurationInRange(minDuration, maxDuration time.Duration) time.Duration {
	if maxDuration <= minDuration {
		return minDuration
	}
	return minDuration + time.Duration(rand.Int64N(int64(maxDuration-minDuration)+1))
}

func IntInRange(minValue, maxValue int) int {
	if maxValue <= minValue {
		return minValue
	}
	return minValue + rand.IntN(maxValue-minValue+1)
}
