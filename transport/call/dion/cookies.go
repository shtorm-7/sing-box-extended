package dion

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

type CookieEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (s *Session) LoadCookies(entries []CookieEntry) error {
	if s.HTTPClient.Jar == nil {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return fmt.Errorf("cookiejar: %w", err)
		}
		s.HTTPClient.Jar = jar
	}
	web, err := url.Parse(WebBase)
	if err != nil {
		return fmt.Errorf("parse target %s: %w", WebBase, err)
	}
	cookies := make([]*http.Cookie, 0, len(entries))
	for _, entry := range entries {
		if entry.Name == "" {
			continue
		}
		cookies = append(cookies, &http.Cookie{
			Name:   entry.Name,
			Value:  entry.Value,
			Path:   "/",
			Domain: CookieDomain,
		})
	}
	s.HTTPClient.Jar.SetCookies(web, cookies)
	s.seedAccessTokenFromCookies(entries)
	return nil
}

func (s *Session) LoadCookieString(cookieStr string) error {
	cookieStr = strings.TrimSpace(cookieStr)
	if cookieStr == "" {
		return fmt.Errorf("empty cookie string")
	}
	var entries []CookieEntry
	for _, piece := range strings.Split(cookieStr, ";") {
		piece = strings.TrimSpace(piece)
		if piece == "" {
			continue
		}
		eq := strings.IndexByte(piece, '=')
		if eq <= 0 {
			continue
		}
		entries = append(entries, CookieEntry{Name: piece[:eq], Value: piece[eq+1:]})
	}
	return s.LoadCookies(entries)
}

func (s *Session) SetCookieInJar(name, value string) {
	if s.HTTPClient == nil || s.HTTPClient.Jar == nil {
		return
	}
	web, err := url.Parse(WebBase)
	if err != nil {
		return
	}
	s.HTTPClient.Jar.SetCookies(web, []*http.Cookie{
		{Name: name, Value: value, Path: "/", Domain: CookieDomain},
	})
}

func (s *Session) HasCredentials() bool {
	return s.email != "" && s.password != ""
}

func (s *Session) HasRefreshCookie() bool {
	if s.HTTPClient == nil || s.HTTPClient.Jar == nil {
		return false
	}
	web, err := url.Parse(WebBase)
	if err != nil {
		return false
	}
	for _, c := range s.HTTPClient.Jar.Cookies(web) {
		if c.Name == refreshCookieName && c.Value != "" {
			return true
		}
	}
	return false
}

func (s *Session) PrimeCookies(slug string) error {
	target := WebBase + "/"
	if slug != "" {
		target = fmt.Sprintf("%s/event/%s?showWeb=true", WebBase, slug)
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	s.setBaseHeaders(req, "")
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("prime cookies: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("prime cookies: status %d", resp.StatusCode)
	}
	return nil
}

func (s *Session) seedAccessTokenFromCookies(entries []CookieEntry) {
	for _, entry := range entries {
		if entry.Name != accessCookieName || entry.Value == "" {
			continue
		}
		exp, err := parseJWTExpiry(entry.Value)
		if err != nil {
			return
		}
		s.AccessToken = entry.Value
		s.AccessTokenExp = exp
		return
	}
}
