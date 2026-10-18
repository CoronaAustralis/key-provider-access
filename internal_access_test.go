package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestInternalModelRequestsBypassKeyPolicies(t *testing.T) {
	for _, test := range []struct {
		name              string
		metadata          map[string]any
		allow             bool
		policyUnavailable bool
	}{
		{name: "internal_without_scope", metadata: map[string]any{"source": "plugin_host_model_callback"}, allow: true},
		{name: "internal_with_restricted_scope", metadata: map[string]any{"source": "plugin_host_model_callback", "caller_scope": scopeA}, allow: true},
		{name: "internal_with_invalid_scope", metadata: map[string]any{"source": "plugin_host_model_callback", "caller_scope": 42}, allow: true},
		{name: "internal_with_unavailable_policy", metadata: map[string]any{"source": "plugin_host_model_callback", "caller_scope": scopeA}, allow: true, policyUnavailable: true},
		{name: "external_without_scope"},
		{name: "external_with_restricted_scope", metadata: map[string]any{"caller_scope": scopeA}},
		{name: "external_with_other_source", metadata: map[string]any{"source": "other", "caller_scope": scopeA}},
		{name: "external_with_invalid_source", metadata: map[string]any{"source": true, "caller_scope": scopeA}},
		{name: "external_with_unavailable_policy", metadata: map[string]any{"caller_scope": scopeA}, policyUnavailable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.policyUnavailable {
				globalState.clear()
				t.Cleanup(globalState.clear)
			} else {
				installTestPolicy(t, policyDocument{Version: 2, Policies: []policyConfig{{
					CallerScope: scopeA, DenyModels: []string{"blocked-model"}, DenyProfiles: []string{"blocked-profile"},
				}}})
			}
			for _, method := range []string{methodRequestInterceptBefore, methodRequestInterceptAfter, methodSchedulerPick} {
				t.Run(method, func(t *testing.T) {
					metadata := make(map[string]any, len(test.metadata)+1)
					for key, value := range test.metadata {
						metadata[key] = value
					}
					metadata["selected_auth_id"] = "blocked-profile"
					var request any = requestInterceptRequest{
						Model: "blocked-model", Metadata: metadata,
						Headers: http.Header{"Source": {"plugin_host_model_callback"}},
						Body:    []byte(`{"source":"plugin_host_model_callback"}`),
					}
					if method == methodSchedulerPick {
						request = schedulerPickRequest{
							Model: "blocked-model", Options: schedulerOptions{Metadata: metadata},
							Candidates: []schedulerAuthCandidate{{ID: "blocked-profile"}},
						}
					}
					raw, err := json.Marshal(request)
					if err != nil {
						t.Fatal(err)
					}
					response, err := handleMethod(method, raw)
					if err != nil {
						t.Fatal(err)
					}
					if method != methodSchedulerPick {
						var result requestInterceptResponse
						unwrapEnvelope(t, response, &result)
						if test.allow {
							if result.Terminate || result.StatusCode != 0 {
								t.Fatalf("internal request was blocked: %s", response)
							}
						} else if !result.Terminate || result.StatusCode != http.StatusForbidden {
							t.Fatalf("external request bypassed policy: %s", response)
						}
						return
					}
					if test.allow {
						var result schedulerPickResponse
						unwrapEnvelope(t, response, &result)
						if result.Handled || result.AuthID != "" {
							t.Fatalf("internal scheduling was not delegated to CPA: %s", response)
						}
						return
					}
					var wrapped envelope
					if err := json.Unmarshal(response, &wrapped); err != nil {
						t.Fatal(err)
					}
					if wrapped.OK || wrapped.Error == nil || wrapped.Error.HTTPStatus != http.StatusForbidden {
						t.Fatalf("external scheduling bypassed policy: %s", response)
					}
				})
			}
		})
	}
}
