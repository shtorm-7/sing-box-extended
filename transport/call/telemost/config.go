package telemost

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

type TMConfig struct {
	AppVersion string
	SDKVersion string
}

func FetchConfig(dialer N.Dialer, logger logger.ContextLogger) (TMConfig, error) {
	var cfg TMConfig
	page, err := common.HttpGet(dialer, "https://telemost.yandex.ru/")
	if err != nil {
		return cfg, fmt.Errorf("failed to fetch telemost.yandex.ru: %w", err)
	}
	stateRe := regexp.MustCompile(`<script[^>]*id="preloaded-state"[^>]*>([\s\S]*?)</script>`)
	stateMatch := stateRe.FindSubmatch(page)
	if stateMatch == nil {
		return cfg, fmt.Errorf("preloaded-state not found in page")
	}
	var state struct {
		Config struct {
			AppVersion string `json:"appVersion"`
		} `json:"config"`
		AppVersion string `json:"appVersion"`
	}
	if err := json.Unmarshal(stateMatch[1], &state); err != nil {
		return cfg, fmt.Errorf("failed to parse preloaded-state: %w", err)
	}
	cfg.AppVersion = state.Config.AppVersion
	if cfg.AppVersion == "" {
		cfg.AppVersion = state.AppVersion
	}
	if cfg.AppVersion == "" {
		return cfg, fmt.Errorf("appVersion not found in preloaded-state")
	}
	logger.Debug(fmt.Sprintf("[config] appVersion=%s", cfg.AppVersion))
	bundleRe := regexp.MustCompile(`https://telemost\.yastatic\.net/s3/telemost/_/main\.\w+\.[a-f0-9]+\.js`)
	bundleURL := bundleRe.FindString(string(page))
	if bundleURL == "" {
		return cfg, fmt.Errorf("main bundle URL not found in page")
	}
	logger.Debug(fmt.Sprintf("[config] Found bundle: %s", bundleURL))
	bundle, err := common.HttpGet(dialer, bundleURL)
	if err != nil {
		return cfg, fmt.Errorf("failed to fetch bundle: %w", err)
	}
	sdkVerPatterns := []*regexp.Regexp{
		regexp.MustCompile(`goloom_sdk_version:"(\d+\.\d+\.\d+)"`),
		regexp.MustCompile(`"@yandex-video-platform/goloom-sdk":"(\d+\.\d+\.\d+)"`),
		regexp.MustCompile(`goloom-sdk\.(\d+\.\d+\.\d+)\.js`),
	}
	for _, re := range sdkVerPatterns {
		if m := re.FindSubmatch(bundle); m != nil {
			cfg.SDKVersion = string(m[1])
			break
		}
	}
	if cfg.SDKVersion == "" {
		return cfg, fmt.Errorf("goloom SDK version not found in bundle")
	}
	logger.Debug(fmt.Sprintf("[config] app=%s sdk=%s", cfg.AppVersion, cfg.SDKVersion))
	return cfg, nil
}
