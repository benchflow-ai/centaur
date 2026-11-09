# Personal Runlayer Plugin access

Sign into Console with Slack SSO, then connect your own Runlayer account in
**Integrations**. DMs and channel turns use the requester's connection; shared
accounts, role grants and email-based matching are unsupported.

```sh
runlayer discover
runlayer search "find recent build failures"
runlayer call EXACT_ADVERTISED_NAME '{"argument":"value"}'
```

Names and schemas come from discovery. Connector consent and approval responses
are returned unchanged. Calls are never automatically retried, and MCP sessions
and tool definitions last only for one CLI invocation.

## Setup

An administrator opens **Integrations** in Console, enters the tenant's exact
HTTPS Plugin MCP URL (ending in `/mcp`) on the Runlayer card, and connects.
Console registers an OAuth client with the tenant and stores the URL as the
app's `provider_config.resource`. Alternatively, create a `runlayer` OAuth App
with that resource, its registered client ID/secret, scope `mcp:proxy`, and
callback `<Console public URL>/oauth/<app-slug>/callback`. Availability in
channels is automatic. No deployment environment variables are needed: the
sandbox CLI reads the resource from Console's sandbox OAuth-app catalog.

The provider uses S256 PKCE, `client_secret_post`, RFC 8707 resource binding,
and same-origin `/api/v1/oauth/{authorize,token,register,revoke}` endpoints;
verify these against the tenant's OAuth metadata. token-broker refreshes
tokens with the same resource. Tokens remain encrypted in Console and are
injected by iron-proxy only for GET/POST/DELETE to the resource host and path.

Disconnect removes local access even if remote revocation fails; follow the
reported Runlayer revocation step in that case. Expired/dead credentials and
disabled apps/users cannot supply tokens. The resource is fixed once the app
exists: for another tenant, create a new app and have each user connect it.

## Validation

Run the Python client, Console `personal_runlayer`, proxy-sync, and token-broker database tests.
Verify two real users' distinct permissions, requester switching, disconnect and
connector consent through a sandbox before rollout.
