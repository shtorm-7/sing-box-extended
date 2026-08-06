package vk

import (
	"fmt"

	"github.com/sagernet/sing/common/logger"
)

type VKConfig struct {
	AppID           string
	APIVersion      string
	SDKVersion      string
	AppVersion      string
	ProtocolVersion string
}

func FetchConfig(logger logger.ContextLogger) (VKConfig, error) {
	cfg := VKConfig{
		AppID:           "6287487",
		APIVersion:      "5.280",
		SDKVersion:      "2.8.6-beta.22",
		AppVersion:      "1.1",
		ProtocolVersion: "6",
	}
	logger.Debug(fmt.Sprintf("[config] app_id=%s api=%s sdk=%s app=%s proto=%s",
		cfg.AppID, cfg.APIVersion, cfg.SDKVersion, cfg.AppVersion, cfg.ProtocolVersion))
	return cfg, nil
}
