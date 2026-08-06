package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"

	"github.com/pion/datachannel"
	"github.com/pion/webrtc/v4"
	"github.com/sagernet/sing/common/logger"
)

const chunkSize = 994

type chunkBuf struct {
	chunks [][]byte
	count  int
	size   int
}

type DCTunnel struct {
	dc       *webrtc.DataChannel
	raw      datachannel.ReadWriteCloser
	writeRaw datachannel.ReadWriteCloser
	logger   logger.ContextLogger
	onData   func([]byte)
	onClose  func()
	obf      *TunnelObfuscator
	chunked  bool
	readBuf  int

	recvBufs  sync.Map
	sendMsgID uint32
}

func NewDCTunnel(dc *webrtc.DataChannel, obf *TunnelObfuscator, readBuf int, logger logger.ContextLogger) *DCTunnel {
	t := &DCTunnel{dc: dc, obf: obf, readBuf: readBuf, logger: logger}
	raw, err := dc.Detach()
	if err != nil {
		logger.Warn(fmt.Sprintf("dctunnel: detach failed, using callback mode: %v", err))
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			t.deliverMessage(msg.Data)
		})
		dc.OnClose(func() {
			if t.onClose != nil {
				t.onClose()
			}
		})
		return t
	}
	t.raw = raw
	go t.readLoop()
	return t
}

func NewDCTunnelFromRaw(dc *webrtc.DataChannel, raw datachannel.ReadWriteCloser, obf *TunnelObfuscator, readBuf int, logger logger.ContextLogger) *DCTunnel {
	t := &DCTunnel{dc: dc, raw: raw, obf: obf, readBuf: readBuf, logger: logger}
	go t.readLoop()
	return t
}

func NewChunkedDCTunnel(readRaw datachannel.ReadWriteCloser, writeDC *webrtc.DataChannel, obf *TunnelObfuscator, readBuf int, logger logger.ContextLogger) *DCTunnel {
	writeRaw, err := writeDC.Detach()
	if err != nil {
		logger.Error(fmt.Sprintf("dctunnel: write DC detach failed: %v", err))
		return nil
	}
	t := &DCTunnel{raw: readRaw, writeRaw: writeRaw, obf: obf, readBuf: readBuf, logger: logger, chunked: true}
	go t.readLoop()
	return t
}

func NewChunkedDCTunnelFromRaw(readRaw, writeRaw datachannel.ReadWriteCloser, obf *TunnelObfuscator, readBuf int, logger logger.ContextLogger) *DCTunnel {
	t := &DCTunnel{raw: readRaw, writeRaw: writeRaw, obf: obf, readBuf: readBuf, logger: logger, chunked: true}
	go t.readLoop()
	return t
}

func (t *DCTunnel) SendData(data []byte) {
	for len(data) >= 4 {
		frameLen := int(binary.BigEndian.Uint32(data[0:4]))
		if frameLen < 5 || 4+frameLen > len(data) {
			return
		}
		body := data[4 : 4+frameLen]
		wire := body
		if t.obf != nil {
			wire = t.obf.EncryptPayload(body)
			if wire == nil {
				data = data[4+frameLen:]
				continue
			}
		}
		if t.chunked {
			t.sendChunked(wire)
		} else {
			t.sendRaw(wire)
		}
		data = data[4+frameLen:]
	}
}

func (t *DCTunnel) SetOnData(fn func([]byte))  { t.onData = fn }
func (t *DCTunnel) OnData() func([]byte)       { return t.onData }
func (t *DCTunnel) SetOnClose(fn func())       { t.onClose = fn }
func (t *DCTunnel) Reconfigure(fps, batch int) {}

func (t *DCTunnel) readLoop() {
	buf := make([]byte, t.readBuf)
	for {
		n, isString, err := t.raw.ReadDataChannel(buf)
		if err != nil {
			if err != io.EOF {
				t.logger.Warn(fmt.Sprintf("dctunnel: read error: %v", err))
			}
			if t.onClose != nil {
				t.onClose()
			}
			return
		}
		if isString {
			continue
		}
		if t.chunked && n >= 6 {
			t.handleChunk(buf[:n])
		} else if n > 0 {
			t.deliverMessage(buf[:n])
		}
	}
}

func (t *DCTunnel) handleChunk(data []byte) {
	id := uint16(data[0])<<8 | uint16(data[1])
	idx := int(uint16(data[2])<<8 | uint16(data[3]))
	total := int(uint16(data[4])<<8 | uint16(data[5]))
	payload := data[6:]
	if total == 1 {
		cp := make([]byte, len(payload))
		copy(cp, payload)
		t.deliverMessage(cp)
		return
	}
	val, _ := t.recvBufs.LoadOrStore(id, &chunkBuf{chunks: make([][]byte, total)})
	cb := val.(*chunkBuf)
	if idx < len(cb.chunks) && cb.chunks[idx] == nil {
		cp := make([]byte, len(payload))
		copy(cp, payload)
		cb.chunks[idx] = cp
		cb.count++
		cb.size += len(cp)
	}
	if cb.count == total {
		t.recvBufs.Delete(id)
		out := make([]byte, 0, cb.size)
		for _, c := range cb.chunks {
			out = append(out, c...)
		}
		t.deliverMessage(out)
	}
}

func (t *DCTunnel) deliverMessage(data []byte) {
	if len(data) == 0 {
		return
	}
	if t.obf != nil {
		pt, ok := t.obf.DecryptPayload(data)
		if !ok {
			t.logger.Debug(fmt.Sprintf("dctunnel: decrypt failed, dropping %d bytes", len(data)))
			return
		}
		data = pt
	}
	if t.onData != nil && len(data) > 0 {
		frame := make([]byte, 4+len(data))
		binary.BigEndian.PutUint32(frame[0:4], uint32(len(data)))
		copy(frame[4:], data)
		t.onData(frame)
	}
}

func (t *DCTunnel) sendChunked(data []byte) {
	w := t.writeRaw
	if w == nil {
		w = t.raw
	}
	if w == nil {
		return
	}
	total := int(math.Ceil(float64(len(data)) / float64(chunkSize)))
	if total == 0 {
		total = 1
	}
	id := uint16(atomic.AddUint32(&t.sendMsgID, 1)) & 0xFFFF
	for i := 0; i < total; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}
		p := data[start:end]
		f := make([]byte, 6+len(p))
		f[0] = byte(id >> 8)
		f[1] = byte(id & 0xFF)
		f[2] = byte(i >> 8)
		f[3] = byte(i & 0xFF)
		f[4] = byte(total >> 8)
		f[5] = byte(total & 0xFF)
		copy(f[6:], p)
		w.Write(f)
	}
}

func (t *DCTunnel) sendRaw(data []byte) {
	w := t.writeRaw
	if w == nil {
		w = t.raw
	}
	if w != nil {
		w.Write(data)
		return
	}
	if t.dc == nil || t.dc.ReadyState() != webrtc.DataChannelStateOpen {
		return
	}
	t.dc.Send(data)
}
