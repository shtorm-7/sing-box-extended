package masque

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/cloudflare"
	"github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// GenerateConfig provisions the MASQUE account into the cache: it keeps the cached
// profile when present, or registers a new one. With recreate it always registers
// a fresh one. It does not start the tunnel.
func (w *Outbound) GenerateConfig(recreate bool) error {
	_, err := w.provisionConfig(recreate)
	return err
}

// provisionConfig returns the MASQUE config, loading it from the cache or creating
// (and caching) a new one. With recreate it ignores the cache and creates a fresh config.
func (w *Outbound) provisionConfig(recreate bool) (*Config, error) {
	cacheFile := service.FromContext[adapter.CacheFile](w.ctx)
	var appConfig *Config
	var err error
	if !recreate && cacheFile != nil && cacheFile.StoreMASQUEConfig() {
		savedProfile := cacheFile.LoadMASQUEConfig(w.Tag())
		if savedProfile != nil {
			if err = json.Unmarshal(savedProfile.Content, &appConfig); err != nil {
				return nil, err
			}
		}
	}
	if appConfig == nil {
		appConfig, err = w.createConfig()
		if err != nil {
			return nil, err
		}
		if cacheFile != nil && cacheFile.StoreMASQUEConfig() {
			content, err := json.Marshal(appConfig)
			if err != nil {
				return nil, err
			}
			cacheFile.SaveMASQUEConfig(w.Tag(), &adapter.SavedBinary{
				LastUpdated: time.Now(),
				Content:     content,
				LastEtag:    "",
			})
		}
	}
	return appConfig, nil
}

func (w *Outbound) createConfig() (*Config, error) {
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
	api := cloudflare.NewCloudflareApi(opts...)
	var profile *cloudflare.CloudflareProfile
	var err error
	if w.options.Profile.AuthToken != "" && w.options.Profile.ID != "" {
		profile, err = api.GetProfile(w.ctx, w.options.Profile.AuthToken, w.options.Profile.ID)
		if err != nil {
			return nil, err
		}
	} else {
		wgPrivateKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		profile, err = api.CreateProfile(w.ctx, wgPrivateKey.PublicKey().String())
		if err != nil {
			return nil, err
		}
	}
	privateKey, publicKey, err := masque.GenerateEcKeyPair()
	if err != nil {
		return nil, E.New("failed to generate key pair: ", err)
	}
	updatedProfile, err := api.EnrollKey(w.ctx, profile.Token, profile.ID, cloudflare.KeyTypeMasque, cloudflare.TunTypeMasque, base64.StdEncoding.EncodeToString(publicKey))
	if err != nil {
		return nil, err
	}
	return &Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(privateKey),
		EndpointV4:     updatedProfile.Config.Peers[0].Endpoint.V4[:len(updatedProfile.Config.Peers[0].Endpoint.V4)-2],
		EndpointV6:     updatedProfile.Config.Peers[0].Endpoint.V6[1 : len(updatedProfile.Config.Peers[0].Endpoint.V6)-3],
		EndpointH2V4:   cloudflare.DefaultEndpointH2V4,
		EndpointH2V6:   cloudflare.DefaultEndpointH2V6,
		EndpointPubKey: updatedProfile.Config.Peers[0].PublicKey,
		License:        updatedProfile.Account.License,
		ID:             updatedProfile.ID,
		AccessToken:    profile.Token,
		IPv4:           updatedProfile.Config.Interface.Addresses.V4,
		IPv6:           updatedProfile.Config.Interface.Addresses.V6,
	}, nil
}
