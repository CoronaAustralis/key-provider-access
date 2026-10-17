package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultManagementURL    = "http://127.0.0.1:8317"
	defaultManagementKeyEnv = "MANAGEMENT_PASSWORD"
	maxCatalogResponseSize  = 16 << 20
)

type catalogConnection struct {
	mu         sync.RWMutex
	sessionKey string
	lastError  string
}

var catalogAccess catalogConnection

// Management calls stay on loopback and never follow redirects or system proxies.
var catalogHTTP = &http.Client{
	Transport: &http.Transport{Proxy: nil},
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func managementURL(cfg pluginConfig) string {
	if value := strings.TrimRight(strings.TrimSpace(cfg.ManagementURL), "/"); value != "" {
		return value
	}
	return defaultManagementURL
}

func validateManagementURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("management_url must be an HTTP(S) loopback origin without credentials, query or fragment")
	}
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("management_url must use localhost or a loopback IP address")
	}
	return nil
}

func (c *catalogConnection) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionKey = ""
	c.lastError = ""
}

func (c *catalogConnection) rememberManagementSession(headers http.Header) {
	key := bearerToken(headers.Get("Authorization"))
	if key == "" {
		key = strings.TrimSpace(headers.Get("X-Management-Key"))
	}
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionKey = key
}

func (c *catalogConnection) credentials(cfg pluginConfig) (string, error) {
	c.mu.RLock()
	key := c.sessionKey
	c.mu.RUnlock()
	if key == "" && cfg.ManagementKeyEnv != "" {
		key = strings.TrimSpace(os.Getenv(cfg.ManagementKeyEnv))
	}
	if key == "" {
		return "", fmt.Errorf("model catalog access needs a management session: open plugin settings or set management_key_env")
	}
	return key, nil
}

func (c *catalogConnection) recordError(err error) {
	message := ""
	if err != nil {
		message = err.Error()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastError = message
}

func (c *catalogConnection) status(cfg pluginConfig) (bool, string) {
	_, err := c.credentials(cfg)
	c.mu.RLock()
	defer c.mu.RUnlock()
	return err == nil, c.lastError
}

func catalogGET(ctx context.Context, cfg pluginConfig, key, path string, target any) error {
	base := managementURL(cfg)
	if err := validateManagementURL(base); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return fmt.Errorf("create catalog management request")
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := catalogHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("catalog management request failed; check management_url and CPA availability")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("catalog management endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCatalogResponseSize+1))
	if err != nil || len(body) > maxCatalogResponseSize {
		return fmt.Errorf("could not read catalog management response")
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("invalid catalog management response")
	}
	return nil
}

func bearerToken(value string) string {
	if parts := strings.SplitN(value, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		return strings.TrimSpace(parts[1])
	}
	return value
}

// catalogCallerScope mirrors CPA's credential order, verifying header candidates
// against the current built-in key set. An invalid first header cannot disguise
// a restricted key supplied through a later header or a query parameter.
func catalogCallerScope(headers http.Header) (string, error) {
	cfg, _, _, _, _, _ := globalState.current()
	key, err := catalogAccess.credentials(cfg)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var response struct {
		Keys []string `json:"api-keys"`
	}
	if err := catalogGET(ctx, cfg, key, "/v0/management/api-keys", &response); err != nil {
		return "", err
	}
	validScopes := make(map[string]struct{}, len(response.Keys))
	for i, raw := range response.Keys {
		validScopes[callerScope(raw)] = struct{}{}
		response.Keys[i] = ""
	}
	for _, raw := range []string{bearerToken(headers.Get("Authorization")), headers.Get("X-Goog-Api-Key"), headers.Get("X-Api-Key")} {
		if raw == "" || raw != strings.TrimSpace(raw) {
			continue
		}
		scope := callerScope(raw)
		if _, ok := validScopes[scope]; ok {
			return scope, nil
		}
	}
	return "", fmt.Errorf("model list caller is unavailable; use Authorization, X-Goog-Api-Key or X-Api-Key instead of query-only authentication")
}

type catalogAuth struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Disabled bool   `json:"disabled"`
	Status   string `json:"status"`
}

// permittedModelProfiles reads actual CPA registry registrations. No provider
// inference is made from model names or the cosmetic owned_by field.
func permittedModelProfiles(scope string, policy runtimePolicy) (map[string][]modelProfile, error) {
	cfg, _, _, _, _, _ := globalState.current()
	key, err := catalogAccess.credentials(cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var response struct {
		Files []catalogAuth `json:"files"`
	}
	if err := catalogGET(ctx, cfg, key, "/v0/management/auth-files", &response); err != nil {
		return nil, err
	}
	aliases, err := catalogLegacyAliases(ctx, cfg, key, response.Files)
	if err != nil {
		return nil, err
	}
	profiles := make([]modelProfile, 0, len(response.Files))
	for _, auth := range response.Files {
		if auth.Disabled || strings.EqualFold(auth.Status, "disabled") || auth.ID == "" {
			continue
		}
		legacy := aliases[auth.ID]
		if legacy != "" {
			globalState.rememberLegacyAlias(scope, auth.ID, legacy)
		}
		if policyAllowsCandidateWithLegacy(policy, auth.ID, auth.Provider, legacy) {
			profiles = append(profiles, modelProfile{ID: auth.ID, Provider: auth.Provider, LegacyID: legacy})
		}
	}
	models := make(map[string][]modelProfile)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstError error
	workers := make(chan struct{}, 8)
	for _, profile := range profiles {
		workers <- struct{}{}
		wg.Add(1)
		go func(profile modelProfile) {
			defer wg.Done()
			defer func() { <-workers }()
			var result struct {
				Models []struct {
					ID string `json:"id"`
				} `json:"models"`
			}
			err := catalogGET(ctx, cfg, key, "/v0/management/auth-files/models?name="+url.QueryEscape(profile.ID), &result)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstError == nil {
					firstError = err
					cancel()
				}
				return
			}
			for _, model := range result.Models {
				if model.ID != "" {
					models[model.ID] = append(models[model.ID], profile)
				}
			}
		}(profile)
	}
	wg.Wait()
	return models, firstError
}
