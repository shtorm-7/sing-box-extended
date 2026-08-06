package wbstream

import (
	"github.com/pion/datachannel"
	"github.com/sagernet/sing-box/transport/call/livekit"
)

type dataPacketWrapper struct {
	inner datachannel.ReadWriteCloser
	kind  int
}

func (w *dataPacketWrapper) ReadDataChannel(p []byte) (int, bool, error) {
	buf := make([]byte, len(p))
	for {
		n, isString, err := w.inner.ReadDataChannel(buf)
		if err != nil {
			return 0, false, err
		}
		if n == 0 {
			continue
		}
		payload, ok := livekit.DecodeDataPacketUser(buf[:n])
		if !ok || len(payload) == 0 {
			continue
		}
		copied := copy(p, payload)
		return copied, isString, nil
	}
}

func (w *dataPacketWrapper) WriteDataChannel(p []byte, isString bool) (int, error) {
	wire := livekit.EncodeDataPacketUser(p, w.kind)
	if _, err := w.inner.WriteDataChannel(wire, isString); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *dataPacketWrapper) Read(p []byte) (int, error) {
	n, _, err := w.ReadDataChannel(p)
	return n, err
}

func (w *dataPacketWrapper) Write(p []byte) (int, error) {
	return w.WriteDataChannel(p, false)
}

func (w *dataPacketWrapper) Close() error { return w.inner.Close() }

func newDataPacketWrapper(inner datachannel.ReadWriteCloser, kind int) *dataPacketWrapper {
	return &dataPacketWrapper{inner: inner, kind: kind}
}
