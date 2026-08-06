package common

import (
	"fmt"

	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
	"github.com/sagernet/sing/common/logger"
)

func AddTunnelTracks(pc *webrtc.PeerConnection, logger logger.ContextLogger, prefix string) *webrtc.TrackLocalStaticSample {
	sampleTrack, _ := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
		"video", "tunnel-video",
	)
	audioTrack, _ := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus},
		"audio", "tunnel-audio",
	)
	audioSender, audioErr := pc.AddTrack(audioTrack)
	videoSender, videoErr := pc.AddTrack(sampleTrack)
	logger.Debug(fmt.Sprintf("%s: AddTrack audio: sender=%v err=%v", prefix, audioSender != nil, audioErr))
	logger.Debug(fmt.Sprintf("%s: AddTrack video: sender=%v err=%v", prefix, videoSender != nil, videoErr))
	logger.Debug(fmt.Sprintf("%s: senders count: %d", prefix, len(pc.GetSenders())))
	return sampleTrack
}

func ReadTrack(track *webrtc.TrackRemote, handler func([]byte), logger logger.ContextLogger, prefix string) {
	if track.Codec().MimeType != webrtc.MimeTypeVP8 {
		buf := make([]byte, UDPBufSize)
		for {
			if _, _, err := track.Read(buf); err != nil {
				return
			}
		}
	}
	var vp8Pkt codecs.VP8Packet
	var pkt rtp.Packet
	var frameBuf []byte
	var lastSeq uint16
	var haveLastSeq bool
	frameValid := false
	recvCount := 0
	buf := make([]byte, RTPBufSize)
	for {
		n, _, err := track.Read(buf)
		if err != nil {
			return
		}
		if pkt.Unmarshal(buf[:n]) != nil {
			continue
		}
		if haveLastSeq && pkt.SequenceNumber != lastSeq+1 {
			frameValid = false
			frameBuf = frameBuf[:0]
		}
		lastSeq = pkt.SequenceNumber
		haveLastSeq = true
		vp8Payload, err := vp8Pkt.Unmarshal(pkt.Payload)
		if err != nil {
			frameValid = false
			frameBuf = frameBuf[:0]
			continue
		}
		if vp8Pkt.S == 1 {
			frameBuf = frameBuf[:0]
			frameValid = true
		}
		if !frameValid {
			continue
		}
		frameBuf = append(frameBuf, vp8Payload...)
		if !pkt.Marker {
			continue
		}
		recvCount++
		if recvCount <= 3 || recvCount%200 == 0 {
			logger.Debug(fmt.Sprintf("%s: recv vp8 frame #%d %d bytes", prefix, recvCount, len(frameBuf)))
		}
		if handler != nil {
			frame := make([]byte, len(frameBuf))
			copy(frame, frameBuf)
			handler(frame)
		}
		frameBuf = frameBuf[:0]
		frameValid = false
	}
}
