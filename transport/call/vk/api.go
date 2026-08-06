package vk

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

type TurnServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
}

type StunServer struct {
	URLs []string `json:"urls"`
}

type CallInfo struct {
	CallID     string
	JoinLink   string
	ShortLink  string
	OKJoinLink string
	TurnServer TurnServer
	StunServer StunServer
	WSEndpoint string
}

type vkTokenResponse struct {
	Data struct {
		AccessToken string `json:"access_token"`
	} `json:"data"`
}

type callSettingsResponse struct {
	Response struct {
		Settings struct {
			PublicKey string `json:"public_key"`
		} `json:"settings"`
	} `json:"response"`
}

type callTokenResponse struct {
	Response struct {
		Token      string `json:"token"`
		APIBaseURL string `json:"api_base_url"`
	} `json:"response"`
}

type okAuthResponse struct {
	SessionKey string `json:"session_key"`
}

type joinResponse struct {
	Endpoint   string     `json:"endpoint"`
	TurnServer TurnServer `json:"turn_server"`
	StunServer StunServer `json:"stun_server"`
}

func JoinExistingCall(dialer N.Dialer, cookieStr, vkLink string, cfg VKConfig, logger logger.ContextLogger) (*CallInfo, error) {
	if cfg.AppID == "" || cfg.APIVersion == "" {
		return nil, fmt.Errorf("config incomplete: app_id=%q api=%q", cfg.AppID, cfg.APIVersion)
	}
	token := extractJoinToken(vkLink)
	if token == "" {
		return nil, fmt.Errorf("could not extract join token from %q", vkLink)
	}
	logger.Info(fmt.Sprintf("[auth] Joining existing call token=%s", token))
	resp, err := authAndJoin(dialer, cookieStr, token, cfg)
	if err != nil {
		return nil, err
	}
	return &CallInfo{
		JoinLink:   vkLink,
		OKJoinLink: token,
		TurnServer: resp.TurnServer,
		StunServer: resp.StunServer,
		WSEndpoint: resp.Endpoint,
	}, nil
}

func CreateAndJoinCall(dialer N.Dialer, cookieStr, peerId string, cfg VKConfig, logger logger.ContextLogger) (*CallInfo, error) {
	if cfg.AppID == "" || cfg.APIVersion == "" {
		return nil, fmt.Errorf("config incomplete: app_id=%q api=%q", cfg.AppID, cfg.APIVersion)
	}
	auth := func(bearer string) map[string]string {
		return map[string]string{"Authorization": "Bearer " + bearer}
	}
	logger.Info("[auth] Getting VK token...")
	r, err := httpPost(dialer, "https://login.vk.com/?act=web_token",
		url.Values{"version": {"1"}, "app_id": {cfg.AppID}},
		map[string]string{"Cookie": cookieStr})
	if err != nil {
		return nil, fmt.Errorf("web_token: %w", err)
	}
	var tok vkTokenResponse
	json.Unmarshal(r, &tok)
	vkToken := tok.Data.AccessToken
	if vkToken == "" {
		return nil, fmt.Errorf("empty VK token, response: %s", string(r))
	}
	logger.Info(fmt.Sprintf("[auth] Creating call peer_id=%s...", peerId))
	r, err = httpPost(dialer, "https://api.vk.com/method/calls.start",
		url.Values{"v": {cfg.APIVersion}, "peer_id": {peerId}}, auth(vkToken))
	if err != nil {
		return nil, fmt.Errorf("calls.start: %w", err)
	}
	var call struct {
		Response struct {
			CallID           string `json:"call_id"`
			JoinLink         string `json:"join_link"`
			OKJoinLink       string `json:"ok_join_link"`
			ShortCredentials struct {
				LinkWithPassword string `json:"link_with_password"`
			} `json:"short_credentials"`
		} `json:"response"`
	}
	json.Unmarshal(r, &call)
	c := call.Response
	if c.CallID == "" {
		return nil, fmt.Errorf("empty call_id, response: %s", string(r))
	}
	if c.OKJoinLink == "" {
		return nil, fmt.Errorf("empty ok_join_link, response: %s", string(r))
	}
	logger.Debug(fmt.Sprintf("[auth] call_id: %s", c.CallID))
	logger.Debug(fmt.Sprintf("[auth] join_link: %s", c.JoinLink))
	logger.Info("[auth] Joining conversation...")
	resp, err := authAndJoin(dialer, cookieStr, c.OKJoinLink, cfg)
	if err != nil {
		return nil, err
	}
	return &CallInfo{
		CallID: c.CallID, JoinLink: c.JoinLink, ShortLink: c.ShortCredentials.LinkWithPassword,
		OKJoinLink: c.OKJoinLink, TurnServer: resp.TurnServer, StunServer: resp.StunServer,
		WSEndpoint: resp.Endpoint,
	}, nil
}

func BuildICEServers(callInfo *CallInfo) []ICEServerSpec {
	var servers []ICEServerSpec
	if len(callInfo.StunServer.URLs) > 0 {
		servers = append(servers, ICEServerSpec{URLs: callInfo.StunServer.URLs})
	}
	if len(callInfo.TurnServer.URLs) > 0 {
		urls := append([]string{}, callInfo.TurnServer.URLs...)
		urls = append(urls, urls[len(urls)-1]+"?transport=tcp")
		servers = append(servers, ICEServerSpec{
			URLs: urls, Username: callInfo.TurnServer.Username, Credential: callInfo.TurnServer.Credential,
		})
	}
	return servers
}

type ICEServerSpec struct {
	URLs       []string
	Username   string
	Credential string
}

func authAndJoin(dialer N.Dialer, cookieStr, okJoinLink string, cfg VKConfig) (*joinResponse, error) {
	auth := func(bearer string) map[string]string {
		return map[string]string{"Authorization": "Bearer " + bearer}
	}
	r, err := httpPost(dialer, "https://login.vk.com/?act=web_token",
		url.Values{"version": {"1"}, "app_id": {cfg.AppID}},
		map[string]string{"Cookie": cookieStr})
	if err != nil {
		return nil, fmt.Errorf("web_token: %w", err)
	}
	var tok vkTokenResponse
	json.Unmarshal(r, &tok)
	if tok.Data.AccessToken == "" {
		return nil, fmt.Errorf("empty VK token, response: %s", string(r))
	}
	r, err = httpPost(dialer, "https://api.vk.com/method/calls.getSettings",
		url.Values{"v": {cfg.APIVersion}}, auth(tok.Data.AccessToken))
	if err != nil {
		return nil, fmt.Errorf("calls.getSettings: %w", err)
	}
	var settings callSettingsResponse
	json.Unmarshal(r, &settings)
	appKey := settings.Response.Settings.PublicKey
	if appKey == "" {
		return nil, fmt.Errorf("empty public_key, response: %s", string(r))
	}
	r, err = httpPost(dialer, "https://api.vk.com/method/messages.getCallToken",
		url.Values{"v": {cfg.APIVersion}, "env": {"production"}}, auth(tok.Data.AccessToken))
	if err != nil {
		return nil, fmt.Errorf("messages.getCallToken: %w", err)
	}
	var callToken callTokenResponse
	json.Unmarshal(r, &callToken)
	if callToken.Response.Token == "" {
		return nil, fmt.Errorf("empty call token, response: %s", string(r))
	}
	if callToken.Response.APIBaseURL == "" {
		return nil, fmt.Errorf("empty api_base_url, response: %s", string(r))
	}
	apiBaseURL := strings.TrimRight(callToken.Response.APIBaseURL, "/")
	if !strings.HasSuffix(apiBaseURL, "/fb.do") {
		apiBaseURL += "/fb.do"
	}
	sd, _ := json.Marshal(map[string]interface{}{
		"device_id": "sing-box-go-1", "client_version": cfg.AppVersion,
		"client_type": "SDK_JS", "auth_token": callToken.Response.Token, "version": 3,
	})
	r, err = httpPost(dialer, apiBaseURL, url.Values{
		"method": {"auth.anonymLogin"}, "application_key": {appKey},
		"format": {"json"}, "session_data": {string(sd)},
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("auth.anonymLogin: %w", err)
	}
	var okAuth okAuthResponse
	json.Unmarshal(r, &okAuth)
	if okAuth.SessionKey == "" {
		return nil, fmt.Errorf("empty session_key, response: %s", string(r))
	}
	ms, _ := json.Marshal(map[string]bool{
		"isAudioEnabled": false, "isVideoEnabled": true, "isScreenSharingEnabled": false,
	})
	r, err = httpPost(dialer, apiBaseURL, url.Values{
		"method": {"vchat.joinConversationByLink"}, "session_key": {okAuth.SessionKey},
		"application_key": {appKey}, "format": {"json"}, "joinLink": {okJoinLink},
		"isVideo": {"true"}, "isAudio": {"false"}, "mediaSettings": {string(ms)},
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("vchat.joinConversationByLink: %w", err)
	}
	var jr joinResponse
	json.Unmarshal(r, &jr)
	if jr.Endpoint == "" {
		return nil, fmt.Errorf("empty WS endpoint, response: %s", string(r))
	}
	return &jr, nil
}

func extractJoinToken(link string) string {
	link = strings.TrimSpace(link)
	if link == "" {
		return ""
	}
	if u, err := url.Parse(link); err == nil && u.Scheme != "" {
		path := strings.Trim(u.Path, "/")
		if path != "" {
			parts := strings.Split(path, "/")
			return parts[len(parts)-1]
		}
	}
	if !strings.ContainsAny(link, "/?&=") {
		return link
	}
	parts := strings.Split(strings.TrimRight(link, "/"), "/")
	return parts[len(parts)-1]
}

func httpPost(dialer N.Dialer, endpoint string, form url.Values, extraHeaders map[string]string) ([]byte, error) {
	body := form.Encode()
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", common.UserAgent)
	req.Header.Set("Origin", "https://vk.com")
	req.Header.Set("Referer", "https://vk.com/")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := common.HttpClient(dialer).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
