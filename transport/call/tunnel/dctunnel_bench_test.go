package tunnel

import (
	"context"
	"io"
	"testing"
)

type discardRawConn struct{}

func (discardRawConn) Read(p []byte) (int, error)                  { return 0, io.EOF }
func (discardRawConn) ReadDataChannel(p []byte) (int, bool, error) { return 0, false, io.EOF }
func (discardRawConn) Write(p []byte) (int, error)                 { return len(p), nil }
func (discardRawConn) WriteDataChannel(p []byte, isString bool) (int, error) {
	return len(p), nil
}
func (discardRawConn) Close() error { return nil }

type benchLogger struct{}

func (benchLogger) Trace(args ...any)                              {}
func (benchLogger) Debug(args ...any)                              {}
func (benchLogger) Info(args ...any)                               {}
func (benchLogger) Notice(args ...any)                             {}
func (benchLogger) Warn(args ...any)                               {}
func (benchLogger) Error(args ...any)                              {}
func (benchLogger) Fatal(args ...any)                              {}
func (benchLogger) Panic(args ...any)                              {}
func (benchLogger) TraceContext(ctx context.Context, args ...any)  {}
func (benchLogger) DebugContext(ctx context.Context, args ...any)  {}
func (benchLogger) InfoContext(ctx context.Context, args ...any)   {}
func (benchLogger) NoticeContext(ctx context.Context, args ...any) {}
func (benchLogger) WarnContext(ctx context.Context, args ...any)   {}
func (benchLogger) ErrorContext(ctx context.Context, args ...any)  {}
func (benchLogger) FatalContext(ctx context.Context, args ...any)  {}
func (benchLogger) PanicContext(ctx context.Context, args ...any)  {}

func newBenchDCTunnel() *DCTunnel {
	return &DCTunnel{raw: discardRawConn{}, logger: benchLogger{}, readBuf: 4096}
}

func BenchmarkDCTunnelSendData(b *testing.B) {
	sizes := []int{64, 512, 4096}
	for _, size := range sizes {
		payload := make([]byte, size)
		frame := EncodeFrame(42, MsgData, payload)
		b.Run(sizeLabel(size), func(b *testing.B) {
			t := newBenchDCTunnel()
			b.ReportAllocs()
			b.SetBytes(int64(len(frame)))
			for i := 0; i < b.N; i++ {
				t.SendData(frame)
			}
		})
	}
}

func sizeLabel(n int) string {
	switch n {
	case 64:
		return "64B"
	case 512:
		return "512B"
	case 4096:
		return "4KB"
	default:
		return "custom"
	}
}
