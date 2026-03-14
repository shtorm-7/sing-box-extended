package parser

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func ParseRawSubscription(ctx context.Context, content string) ([]option.Outbound, error) {
	if base64Content, err := DecodeBase64URLSafe(content); err == nil {
		servers, _ := parseRawSubscription(base64Content)
		if len(servers) > 0 {
			return servers, err
		}
	}
	return parseRawSubscription(content)
}

func parseRawSubscription(content string) ([]option.Outbound, error) {
	var servers []option.Outbound
	content = strings.ReplaceAll(content, "\r\n", "\n")
	linkList := strings.Split(content, "\n")
	for _, linkLine := range linkList {
		server, err := ParseSubscriptionLink(linkLine)
		if err != nil {
			continue
		}
		servers = append(servers, server)
	}
	if len(servers) == 0 {
		return nil, E.New("no servers found")
	}
	return servers, nil
}

func DecodeBase64URLSafe(content string) (string, error) {
	s := strings.ReplaceAll(content, " ", "-")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "=", "")
	result, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return content, nil
	}
	return string(result), nil
}
