package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

func requestedModel(original, current string) string {
	if model := strings.TrimSpace(original); model != "" {
		return model
	}
	return strings.TrimSpace(current)
}

func requestedModelFromScheduler(req schedulerPickRequest) string {
	original, _ := req.Options.Metadata["requested_model"].(string)
	return requestedModel(original, req.Model)
}

func hasProfileRules(policy runtimePolicy) bool {
	return len(policy.AllowProfiles) > 0 || len(policy.DenyProfiles) > 0
}

func modelAllowed(policy runtimePolicy, model string) bool {
	if len(policy.AllowModels) == 0 && len(policy.DenyModels) == 0 {
		return true
	}
	if model == "" {
		return false
	}
	for _, pattern := range policy.DenyModels {
		if wildcardMatch(pattern, model) {
			return false
		}
	}
	if len(policy.AllowModels) == 0 {
		return true
	}
	for _, pattern := range policy.AllowModels {
		if wildcardMatch(pattern, model) {
			return true
		}
	}
	return false
}

func terminatedModelResponse(model string) ([]byte, error) {
	body, err := json.Marshal(map[string]any{"error": map[string]string{
		"type": "model_access_denied", "message": "model is not allowed for this API key", "model": model,
	}})
	if err != nil {
		return nil, err
	}
	return okEnvelope(requestInterceptResponse{
		Terminate: true, StatusCode: http.StatusForbidden,
		ResponseHeaders: http.Header{"Content-Type": {"application/json; charset=utf-8"}},
		ResponseBody:    body,
	})
}

type modelProfile struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	LegacyID string `json:"legacy_id"`
}

// interceptModelList recognizes the existing CPA catalog response contract.
// It does not require custom host metadata or change generation responses.
func interceptModelList(raw []byte) ([]byte, error) {
	var req responseInterceptRequest
	if err := decodeJSON(raw, &req); err != nil {
		return nil, err
	}
	catalog, isCatalog := modelListPayload(req)
	if !isCatalog {
		return okEnvelope(responseInterceptResponse{})
	}
	_, snapshot, _, _, _, _ := globalState.current()
	if !snapshot.BlockAll && len(snapshot.ByCallerScope) == 0 {
		return okEnvelope(responseInterceptResponse{})
	}
	block := snapshot.BlockAll
	var policy runtimePolicy
	var profiles map[string][]modelProfile
	if !block {
		scope, hasScope := callerScopeFromMetadata(req.Metadata)
		if !hasScope {
			var err error
			scope, err = catalogCallerScope(req.RequestHeaders)
			if err != nil {
				catalogAccess.recordError(err)
				block = true
			}
		}
		if !block {
			var configured bool
			policy, configured = snapshot.ByCallerScope[scope]
			if !configured {
				return okEnvelope(responseInterceptResponse{})
			}
			if hasProfileRules(policy) {
				var err error
				profiles, err = permittedModelProfiles(scope, policy)
				if err != nil {
					catalogAccess.recordError(err)
					block = true
				}
			}
		}
	}
	if !block {
		catalogAccess.recordError(nil)
	}
	return filteredModelList(req, catalog, policy, profiles, block)
}

func modelListPayload(req responseInterceptRequest) (map[string]json.RawMessage, bool) {
	if req.Stream || req.Model != "" || req.RequestedModel != "" || len(req.OriginalRequest) != 0 || len(req.RequestBody) != 0 || req.StatusCode != http.StatusOK {
		return nil, false
	}
	var catalog map[string]json.RawMessage
	if json.Unmarshal(req.Body, &catalog) != nil {
		return nil, false
	}
	for _, field := range []string{"data", "models"} {
		value, ok := catalog[field]
		if ok && len(value) > 0 && value[0] == '[' {
			return catalog, true
		}
	}
	return nil, false
}

func filteredModelList(req responseInterceptRequest, catalog map[string]json.RawMessage, policy runtimePolicy, profiles map[string][]modelProfile, block bool) ([]byte, error) {
	for _, field := range []string{"data", "models"} {
		items, exists := catalog[field]
		if !exists {
			continue
		}
		var models []json.RawMessage
		if err := json.Unmarshal(items, &models); err != nil {
			return nil, err
		}
		visible := make([]json.RawMessage, 0, len(models))
		for _, item := range models {
			id := catalogModelID(item, req.SourceFormat)
			if block || id == "" || !modelAllowed(policy, id) {
				continue
			}
			if hasProfileRules(policy) && len(profiles[id]) == 0 {
				continue
			}
			visible = append(visible, item)
		}
		catalog[field], _ = json.Marshal(visible)
		// Anthropic pagination identifiers must not reveal filtered models.
		for _, edge := range []struct {
			field string
			index int
		}{{"first_id", 0}, {"last_id", len(visible) - 1}} {
			if _, exists := catalog[edge.field]; !exists {
				continue
			}
			id := ""
			if len(visible) > 0 {
				var entry struct {
					ID string `json:"id"`
				}
				_ = json.Unmarshal(visible[edge.index], &entry)
				id = entry.ID
			}
			catalog[edge.field], _ = json.Marshal(id)
		}
	}
	body, err := json.Marshal(catalog)
	if err != nil {
		return nil, err
	}
	return okEnvelope(responseInterceptResponse{Body: body, Headers: http.Header{"Cache-Control": {"no-store"}}, ClearHeaders: []string{"Content-Length", "ETag"}})
}

func catalogModelID(raw json.RawMessage, source string) string {
	var model struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
		Name string `json:"name"`
	}
	if json.Unmarshal(raw, &model) != nil {
		return ""
	}
	id := requestedModel(model.ID, model.Slug)
	if id == "" {
		id = strings.TrimPrefix(model.Name, "models/")
	}
	if source == "claude" && strings.HasPrefix(id, "claude-fable-5-dd-") {
		runes := []rune(strings.TrimPrefix(id, "claude-fable-5-dd-"))
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		id = string(runes)
	}
	return strings.TrimSpace(id)
}
