# CPA Key Model and Provider Access

`key-provider-access` 0.2.0 combines `key-model-access` model rules with upstream provider/profile rules in one native plugin. **CPA source and binaries do not need modification or rebuilding.** The plugin ID, library name, settings URL and default policy location remain `key-provider-access`.

CPA authenticates downstream keys. Generation requests use its existing `Metadata.caller_scope`. Catalog filtering uses CPA's existing `response.intercept_after` hook, without custom host fields or additional CPA endpoints.

## Permissions

Version 2 policies support four optional arrays:

- `allow_models` / `deny_models`: requested model IDs, before upstream alias rewriting.
- `allow_profiles` / `deny_profiles`: CPA upstream credential IDs, including OAuth and API-key provider configurations.

Both dimensions must permit access. Deny wins within each dimension. A non-empty allow list is a whitelist; an empty allow list permits everything not denied. A key without a policy permits all access. `*` matches any number of characters (including `/`); `?` matches one character. Matching is case-sensitive.

The scheduler filters candidates, then round-robins the highest-priority allowed tier. The after-auth hook checks the selected credential again. Unknown/rotated profile IDs are never automatically adopted, and the UI never expands or deletes exact rules when profiles change. Legacy pre-v7.2.146 API-key profile IDs remain supported.

## Model list filtering on stock CPA

The supplied stock CPA source already sends model catalogs through its response interceptor, including OpenAI/Anthropic `/v1/models`, Codex `client_version` catalogs and Gemini `/v1beta/models`. The plugin recognizes this existing response contract and keeps original model objects and protocol envelopes. Anthropic cloaked IDs and Gemini's `models/` prefix are resolved for matching; Anthropic pagination IDs are updated after filtering.

Stock CPA does not include caller identity or per-profile model registrations in these response callbacks. The plugin therefore uses existing **read-only management APIs** on the same CPA instance:

1. `/v0/management/api-keys` verifies which header credential CPA accepted, following CPA's header priority. Raw keys are only used transiently to derive scopes.
2. `/v0/management/auth-files` lists enabled runtime profiles, including API-key profiles.
3. `/v0/management/auth-files/models?name=<profile-id>` returns each permitted profile's actual registry registrations.
4. Provider key configuration endpoints are read when needed to reproduce legacy profile IDs; provider secrets are transient and never saved or logged.

A model appears only when its model rule permits it and at least one permitted supporting profile exists when profile rules are configured. Shared models remain visible if any permitted profile supports them. Model names and `owned_by` labels are not used to guess which profiles support a model. Registrations are read for each catalog request, so refreshing/saving the UI is not required after upstream model changes.

Generation, streaming and scheduling do not depend on management connectivity. If policies exist and catalog identity/management data is unavailable, the list is empty rather than exposing a global catalog. The settings overview and status endpoint show the last catalog connection error.

### Management connection

Set `management_url` to this CPA instance's **local** HTTP(S) origin; the default is `http://127.0.0.1:8317`. Change the port/TLS/base path when necessary. Only `localhost` and loopback IPs are accepted. Requests bypass system proxies and redirects are not followed. A Docker plugin runs inside CPA's container, so use CPA's internal listening port.

Management authentication has two options:

- **Settings session:** open the plugin settings page while signed into same-origin CPAMC with “remember password” enabled. The page's authenticated plugin management requests supply the Management Key to the backend, which retains it **only in process memory**. Open the page again after CPA/plugin restarts.
- **Unattended operation:** put the existing CPA Management Key in an environment variable visible to CPA and configure its name through `management_key_env` (default: `MANAGEMENT_PASSWORD`). This does not change or create CPA's actual Management Key; the value must already be accepted by CPA. No raw Management Key needs to be placed in plugin configuration or policies.

### Public API limits

- Use `Authorization: Bearer <CPA-key>`, `X-Goog-Api-Key`, or `X-Api-Key` for model-list requests. CPA's stock response hook does not carry URL query parameters; query-only authentication produces an empty list whenever policies exist. Generation continues to use CPA's caller scope as before.
- CPA builds must actually expose model lists to `response.intercept_after`, as the supplied source does. An older build without that existing hook cannot be made to filter its own `/v1/models` route by installing a plugin alone.
- Stock CPA's separate Gemini model-detail GET handler bypasses this response hook; its detail response cannot be hidden through this plugin ABI. This does not affect `/v1beta/models` list filtering or generation enforcement. OpenAI/Anthropic detail routes that select from the intercepted catalog inherit filtering.
- CPA Home bypasses plugin scheduling and does not expose remote credential registrations locally. Profile-restricted Home models without local registrations remain hidden; the after-auth check cannot reroute a disallowed Home credential.
- Separate Live/realtime and alpha/search paths remain subject to CPA's existing hook coverage. This plugin does not add interception to the host.

## Build and install

```bash
make build
make install CPA_DIR=/path/to/CLIProxyAPI
```

The Linux amd64 output is `dist/key-provider-access.so`. For other OS/architectures, build the c-shared library on the target platform. Install the library in CPA's `plugins/<GOOS>/<GOARCH>/` directory. Restart/reload plugins using CPA's normal mechanism; keep the stock CPA executable.

```yaml
api-keys:
  - "replace-with-a-real-api-key"

plugins:
  enabled: true
  dir: "plugins"
  configs:
    key-model-access:
      enabled: false
    key-provider-access:
      enabled: true
      priority: 100
      management_url: "http://127.0.0.1:8317"
      management_key_env: "MANAGEMENT_PASSWORD"
      version: 2
      policies: []
```

Only one scheduler plugin is active in CPA. Give this plugin the highest scheduler priority when profile restrictions must control candidate selection.

## Merge existing policies

Back up both policy files. Existing provider-only v2 policies remain valid. Merge model rules into the provider document by matching **`caller_scope`**, preserving scopes and provider rules from either document. Copy `allow_models` and `deny_models` from the old model policy. Missing arrays default to empty. Disable `key-model-access` after merging its rules.

```toml
version = 2

[[policies]]
caller_scope = "f7291f3315e5ab0d3c02015a081879d748693f231d8370b43f38f57be991734a"
allow_models = ["gpt-*", "claude-*"]
deny_models = ["*-preview"]
allow_profiles = ["codex:apikey:abc123def456", "oauth-profile-id"]
deny_profiles = ["*-retired"]
```

YAML and JSON use the same version 2 schema. Unknown fields and duplicate/invalid scopes are rejected. `policy_file`, when configured, is authoritative; inline policies are ignored. An initially missing/invalid file fails closed. Invalid subsequent reloads preserve the last valid policy.

## Management UI and persistence

Open `/v0/resource/plugins/key-provider-access/settings` or the CPAMC plugin menu entry. Each key has model and provider selectors with allow/deny rules, search, wildcards and multi-select. The model picker reads registry registrations through management authentication, so a restricted downstream key cannot hide editor options.

On first use the page initializes `<plugins.dir>/key-provider-access/config.toml` and patches this plugin's `policy_file`. Updates retain revision ETags and atomic file replacement. Persist the writable plugin directory in Docker, rather than bind-mounting a single policy file. Policies never store raw downstream/upstream keys or the Management Key.

Existing management routes remain:

- `GET /v0/management/plugins/key-provider-access/status`
- `GET/PUT /v0/management/plugins/key-provider-access/policies`
- `POST /v0/management/plugins/key-provider-access/reload`
- `POST /v0/management/plugins/key-provider-access/initialize-storage`

## Manual check

Configure `allow_models: ["gpt-*"]`, `deny_models: ["*-preview"]` and a specific allowed profile. Open settings once or supply the Management Key environment variable. Verify that `/v1/models` using that key's Authorization header lists only permitted models supported by the allowed profile, forbidden generation requests return 403, shared models survive if an allowed profile supports them, and an unconfigured key sees the normal catalog. Check Gemini/Anthropic lists if those clients are used.
