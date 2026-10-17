package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// catalogLegacyAliases derives both CPA identity formats from read-only provider
// config responses. Credentials remain transient, just as in the existing UI.
func catalogLegacyAliases(ctx context.Context, cfg pluginConfig, managementKey string, auths []catalogAuth) (map[string]string, error) {
	aliases := make(map[string]string)
	for _, provider := range []string{"gemini", "gemini-interactions", "claude", "codex", "xai"} {
		kind := provider + ":apikey"
		needed := false
		for _, auth := range auths {
			if !auth.Disabled && !strings.EqualFold(auth.Status, "disabled") && strings.HasPrefix(auth.ID, kind+":") {
				needed = true
				break
			}
		}
		if !needed {
			continue
		}
		field := provider + "-api-key"
		if provider == "gemini-interactions" {
			field = "interactions-api-key"
		}
		var response map[string][]struct {
			Key     string            `json:"api-key"`
			BaseURL string            `json:"base-url"`
			Proxy   string            `json:"proxy-url"`
			Prefix  string            `json:"prefix"`
			Headers map[string]string `json:"headers"`
		}
		if err := catalogGET(ctx, cfg, managementKey, "/v0/management/"+field, &response); err != nil {
			return nil, err
		}
		counts := make(map[string]int)
		for i, entry := range response[field] {
			names := make([]string, 0, len(entry.Headers))
			for name := range entry.Headers {
				names = append(names, name)
			}
			sort.Strings(names)
			var headers strings.Builder
			for _, name := range names {
				headers.WriteString(name)
				headers.WriteByte(0)
				headers.WriteString(entry.Headers[name])
				headers.WriteByte(0)
			}
			parts := []string{kind, entry.Key, entry.BaseURL, entry.Proxy, entry.Prefix, headers.String()}
			for j := range parts {
				parts[j] = strings.TrimSpace(parts[j])
			}
			sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
			baseID := kind + ":" + hex.EncodeToString(sum[:])[:12]
			id := baseID
			if count := counts[baseID]; count > 0 {
				id = fmt.Sprintf("%s-%d", baseID, count)
			}
			counts[baseID]++
			aliases[id] = legacyAPIKeyProfileID(schedulerAuthCandidate{
				ID: id, Attributes: map[string]string{"api_key": entry.Key, "base_url": entry.BaseURL},
			})
			response[field][i].Key = ""
		}
	}
	return aliases, nil
}
