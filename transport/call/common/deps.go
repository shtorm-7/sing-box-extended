package common

import (
	"github.com/pion/webrtc/v4"
	"github.com/sagernet/sing/common/logger"
)

type ResolveFunc func(hostname string) (string, error)

type PeerConnectionConfigurer interface {
	ConfigureSettingEngine(settingEngine *webrtc.SettingEngine)
}

type AddTunnelTracksFunc func(pc *webrtc.PeerConnection, logger logger.ContextLogger, prefix string) *webrtc.TrackLocalStaticSample
type ReadTrackFunc func(track *webrtc.TrackRemote, handler func([]byte), logger logger.ContextLogger, prefix string)
