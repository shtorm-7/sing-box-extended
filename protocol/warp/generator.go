package warp

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/cloudflare"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// GenerateConfig provisions the WARP account into the cache: it keeps the cached
// profile when present, or registers a new one. With recreate it always registers
// a fresh one. It does not start the endpoint.
func (w *Endpoint) GenerateConfig(recreate bool) error {
	_, err := w.provisionConfig(recreate)
	return err
}

// provisionConfig returns the WARP config, loading it from the cache or creating
// (and caching) a new one. With recreate it ignores the cache and creates a fresh config.
func (w *Endpoint) provisionConfig(recreate bool) (*Config, error) {
	cacheFile := service.FromContext[adapter.CacheFile](w.ctx)
	var config *Config
	var err error
	if !recreate && cacheFile != nil && cacheFile.StoreWARPConfig() {
		savedProfile := cacheFile.LoadWARPConfig(w.Tag())
		if savedProfile != nil {
			if err = json.Unmarshal(savedProfile.Content, &config); err != nil {
				return nil, err
			}
		}
	}
	if config == nil {
		config, err = w.createConfig()
		if err != nil {
			return nil, err
		}
		if cacheFile != nil && cacheFile.StoreWARPConfig() {
			content, err := json.Marshal(config)
			if err != nil {
				return nil, err
			}
			cacheFile.SaveWARPConfig(w.Tag(), &adapter.SavedBinary{
				LastUpdated: time.Now(),
				Content:     content,
				LastEtag:    "",
			})
		}
	}
	return config, nil
}

func (w *Endpoint) createConfig() (*Config, error) {
	opts := make([]cloudflare.CloudflareApiOption, 0, 1)
	if w.options.Profile.Detour != "" {
		detour, ok := service.FromContext[adapter.OutboundManager](w.ctx).Outbound(w.options.Profile.Detour)
		if !ok {
			return nil, E.New("outbound detour not found: ", w.options.Profile.Detour)
		}
		opts = append(opts, cloudflare.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
		}))
	}
	var privateKey wgtypes.Key
	var err error
	if w.options.Profile.PrivateKey != "" {
		privateKey, err = wgtypes.ParseKey(w.options.Profile.PrivateKey)
		if err != nil {
			return nil, err
		}
	} else {
		privateKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
	}
	api := cloudflare.NewCloudflareApi(opts...)
	var profile *cloudflare.CloudflareProfile
	if w.options.Profile.AuthToken != "" && w.options.Profile.ID != "" {
		profile, err = api.GetProfile(w.ctx, w.options.Profile.AuthToken, w.options.Profile.ID)
		if err != nil {
			return nil, err
		}
	} else {
		profile, err = api.CreateProfile(w.ctx, privateKey.PublicKey().String())
		if err != nil {
			return nil, err
		}
	}
	return &Config{
		PrivateKey: privateKey.String(),
		Interface:  profile.Config.Interface,
		Peers:      profile.Config.Peers,
	}, nil
}
