package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestModelListMatchesCombinedPermissions(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 2, Policies: []policyConfig{{
		CallerScope: scopeA, AllowModels: []string{"gpt-*"}, DenyModels: []string{"*-preview"},
		AllowProfiles: []string{"allowed"}, DenyProfiles: []string{"denied"},
	}}})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-management" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v0/management/api-keys":
			_, _ = w.Write([]byte(`{"api-keys":["secret-a","secret-b"]}`))
		case "/v0/management/auth-files":
			_, _ = w.Write([]byte(`{"files":[{"id":"allowed"},{"id":"denied"}]}`))
		case "/v0/management/auth-files/models":
			if r.URL.Query().Get("name") != "allowed" {
				t.Error("queried forbidden profile")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"models":[{"id":"gpt-visible"},{"id":"gpt-preview"},{"id":"gpt-shared"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	previous := catalogHTTP
	catalogHTTP = &http.Client{Transport: catalogTestTransport(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Result(), nil
	})}
	t.Cleanup(func() { catalogHTTP = previous })
	catalogAccess.rememberManagementSession(http.Header{"Authorization": {"Bearer test-management"}})
	for _, source := range []string{"openai", "claude", "gemini", "codex"} {
		t.Run(source, func(t *testing.T) {
			field, idField := "data", "id"
			if source == "gemini" {
				field, idField = "models", "name"
			} else if source == "codex" {
				field, idField = "models", "slug"
			}
			models := []map[string]string{}
			for _, id := range []string{"gpt-visible", "gpt-denied-profile", "gpt-preview", "claude-hidden", "gpt-shared"} {
				if source == "gemini" {
					id = "models/" + id
				}
				models = append(models, map[string]string{idField: id})
			}
			body, _ := json.Marshal(map[string]any{field: models, "first_id": "hidden", "last_id": "hidden"})
			request := responseInterceptRequest{SourceFormat: source, Body: body, StatusCode: http.StatusOK,
				RequestHeaders: http.Header{"Authorization": {"Bearer secret-a"}},
			}
			raw, _ := json.Marshal(request)
			result, err := interceptModelList(raw)
			if err != nil {
				t.Fatal(err)
			}
			var response responseInterceptResponse
			unwrapEnvelope(t, result, &response)
			var filtered map[string]json.RawMessage
			if err := json.Unmarshal(response.Body, &filtered); err != nil {
				t.Fatal(err)
			}
			var visible []json.RawMessage
			_ = json.Unmarshal(filtered[field], &visible)
			ids := []string{}
			for _, model := range visible {
				ids = append(ids, catalogModelID(model, source))
			}
			if !reflect.DeepEqual(ids, []string{"gpt-visible", "gpt-shared"}) {
				t.Fatalf("visible = %v", ids)
			}
			// The same configured key fails closed when caller identity is missing.
			request.RequestHeaders = nil
			raw, _ = json.Marshal(request)
			result, err = interceptModelList(raw)
			if err != nil {
				t.Fatal(err)
			}
			unwrapEnvelope(t, result, &response)
			_ = json.Unmarshal(response.Body, &filtered)
			_ = json.Unmarshal(filtered[field], &visible)
			if len(visible) != 0 {
				t.Fatal("missing identity exposed catalog")
			}
		})
	}
	for _, tc := range []struct {
		name    string
		headers http.Header
		want    int
	}{
		{"unconfigured key", http.Header{"Authorization": {"Bearer secret-b"}}, 2},
		{"later valid header", http.Header{"Authorization": {"Bearer invalid"}, "X-Api-Key": {"secret-a"}}, 1},
		{"first valid header wins", http.Header{"Authorization": {"Bearer secret-b"}, "X-Api-Key": {"secret-a"}}, 2},
		{"padded invalid header", http.Header{"Authorization": {"secret-b "}, "X-Api-Key": {"secret-a"}}, 1},
		{"query-only unavailable", nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"data":[{"id":"gpt-visible"},{"id":"gpt-denied-profile"}]}`)
			req := responseInterceptRequest{SourceFormat: "openai", StatusCode: http.StatusOK, Body: body, RequestHeaders: tc.headers}
			raw, _ := json.Marshal(req)
			result, err := interceptModelList(raw)
			if err != nil {
				t.Fatal(err)
			}
			var response responseInterceptResponse
			unwrapEnvelope(t, result, &response)
			if len(response.Body) != 0 {
				body = response.Body
			}
			var catalog struct {
				Data []json.RawMessage `json:"data"`
			}
			_ = json.Unmarshal(body, &catalog)
			if len(catalog.Data) != tc.want {
				t.Fatalf("got %s, want %d models", body, tc.want)
			}
		})
	}
	// The same JSON in a generation response must not be mistaken for a catalog.
	raw, _ := json.Marshal(responseInterceptRequest{StatusCode: http.StatusOK, Model: "gpt-visible", Body: []byte(`{"data":[{"id":"untouched"}]}`)})
	result, err := interceptModelList(raw)
	if err != nil {
		t.Fatal(err)
	}
	var unchanged responseInterceptResponse
	unwrapEnvelope(t, result, &unchanged)
	if len(unchanged.Body) != 0 {
		t.Fatal("generation response was modified")
	}
	catalogAccess.clear()
	raw, _ = json.Marshal(responseInterceptRequest{StatusCode: http.StatusOK, RequestHeaders: http.Header{"Authorization": {"Bearer secret-a"}}, Body: []byte(`{"data":[{"id":"gpt-visible"}]}`)})
	result, err = interceptModelList(raw)
	if err != nil {
		t.Fatal(err)
	}
	var unavailable responseInterceptResponse
	unwrapEnvelope(t, result, &unavailable)
	if string(unavailable.Body) != `{"data":[]}` {
		t.Fatalf("missing management connection exposed models: %s", unavailable.Body)
	}
}

func TestCombinedModelRequestAndScheduler(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 2, Policies: []policyConfig{{
		CallerScope: scopeA, AllowModels: []string{"public-*"}, AllowProfiles: []string{"allowed-*"},
	}}})
	if !callIntercept(t, requestInterceptRequest{
		RequestedModel: "private-model", Model: "public-alias", Metadata: map[string]any{"caller_scope": scopeA, "selected_auth_id": "allowed-a"},
	}).Terminate {
		t.Fatal("requested model policy was bypassed by upstream alias")
	}
	req := schedulerPickRequest{
		Model: "public-model", Options: schedulerOptions{Metadata: map[string]any{"caller_scope": scopeA}},
		Candidates: []schedulerAuthCandidate{{ID: "denied", Priority: 100}, {ID: "allowed-a", Priority: 2}, {ID: "allowed-b", Priority: 1}},
	}
	raw, _ := json.Marshal(req)
	result, err := pickProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	var picked schedulerPickResponse
	unwrapEnvelope(t, result, &picked)
	if picked.AuthID != "allowed-a" {
		t.Fatalf("selected %q, want highest-priority allowed profile", picked.AuthID)
	}
	req.Model = "private-model"
	raw, _ = json.Marshal(req)
	result, err = pickProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	var wrapped envelope
	_ = json.Unmarshal(result, &wrapped)
	if wrapped.OK || wrapped.Error == nil || wrapped.Error.HTTPStatus != http.StatusForbidden {
		t.Fatalf("scheduler allowed forbidden model: %s", result)
	}
}

func TestModelOnlyPolicyNeedsNoSelectedProfile(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 2, Policies: []policyConfig{{CallerScope: scopeA, AllowModels: []string{"public"}}}})
	if callIntercept(t, requestInterceptRequest{RequestedModel: "public", Metadata: map[string]any{"caller_scope": scopeA}}).Terminate {
		t.Fatal("model-only policy required a selected profile")
	}
	encoded := []byte(`{"id":"claude-fable-5-dd-cilbup"}`)
	if catalogModelID(encoded, "claude") != "public" {
		t.Fatal("cloaked Anthropic model did not resolve to requested model")
	}
}

type catalogTestTransport func(*http.Request) (*http.Response, error)

func (f catalogTestTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
