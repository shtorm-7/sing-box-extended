package tunnel

import (
	"fmt"
	"sync"
	"time"

	"github.com/sagernet/sing/common/logger"
)

const configResendPeriod = 3 * time.Second

type ConfigAckTracker struct {
	mu        sync.Mutex
	acked     chan struct{}
	cancel    chan struct{}
	confirmed bool
}

func (t *ConfigAckTracker) Acknowledged() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.confirmed
}

func (t *ConfigAckTracker) Arm() (acked, cancel chan struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cancel != nil {
		close(t.cancel)
	}
	t.acked = make(chan struct{})
	t.cancel = make(chan struct{})
	return t.acked, t.cancel
}

func (t *ConfigAckTracker) Mark() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.confirmed = true
	if t.acked == nil {
		return
	}
	select {
	case <-t.acked:
	default:
		close(t.acked)
	}
}

func SendVP8ConfigUntilAcked(acked, cancel <-chan struct{}, stopCh <-chan struct{}, tun DataTunnel, fps, batch, trackCount int, logger logger.ContextLogger, logPrefix string) {
	tun.SendData(EncodeVP8Config(fps, batch, trackCount))
	ticker := time.NewTicker(configResendPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-acked:
			return
		case <-cancel:
			return
		case <-stopCh:
			return
		case <-ticker.C:
			logger.Debug(fmt.Sprintf("%s: resending vp8 config fps=%d batch=%d trackCount=%d, no ack yet",
				logPrefix, fps, batch, trackCount))
			tun.SendData(EncodeVP8Config(fps, batch, trackCount))
		}
	}
}
