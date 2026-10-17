# What this connector stores

This covers the hosted Worker. Each item names the code that handles it. The Worker has no `console.*` calls (a test checks this), and `wrangler.toml.example` turns Worker observability off. Cloudflare still keeps its own platform request metadata, which this code cannot switch off.

## Per user (one Durable Object per sign-in, `worker/user-do.js`)

| Data | Form | Removed |
|---|---|---|
| Hue access and refresh tokens | plain text in Durable Object storage (Cloudflare encrypts it at rest; the app adds no second layer) | on disconnect, or by the cleanup alarm when no MCP code or token is left alive |
| Bridge app key (lets the Worker act on your bridge) | plain text, same storage | on disconnect or cleanup; the key is also removed from your bridge when no other sign-in uses it |
| Sign-in id and bridge registry name | a random id, and `bridge:<sha256 of the bridge id>` | on disconnect or cleanup |
| MCP codes, access tokens, refresh tokens | SHA-256 hash only (`worker/do/tokens.js`), with the client id's hash, the audience and the sign-in time; a code also keeps its redirect URI and PKCE challenge | code after 10 minutes, access token after 1 hour, refresh token after 30 days, all no later than 180 days after sign-in |
| Reuse markers for used codes, rotated refresh tokens and revoked sign-ins | a hash or a random id, and an expiry | when the sign-in's tokens could no longer be valid |
| Disconnected flag | the value `true` only, so a wiped sign-in cannot come back | stays with the empty Durable Object |
| Light names and ids | not stored. A per-user name-to-id cache lives in Worker memory | after 5 minutes, or when the Worker restarts |

## Shared

- Bridge registry (`bridge:<sha256 of bridge id>`, `worker/do/registry.js`): the shared bridge key, the sign-in ids that use it, and per-day counts of sign-ins and Hue calls for that bridge. Daily counts are deleted two days after their date.
- Quota counter (`global`): one number per day.
- Client registration stores nothing. The client id is a signed copy of the client name and redirect URIs.

## In your browser during sign-in

Two cookies, both HttpOnly and deleted after 10 minutes or when used (`worker/session.js`): `hue_consent` holds a random value that ties your approval to your browser, and `hue_login` holds a signed copy of the sign-in request (a hash of the client id, the redirect URI, the PKCE challenge, the client's `state` and a random nonce). Nothing about the sign-in is stored on the server until Hue confirms it.

## Retention

- A sign-in lasts while your MCP client keeps refreshing, for at most 180 days. After that, or after 30 days without use, the cleanup alarm deletes its data and you sign in again.
- When you remove the connector, MCP clients that support token revocation call `POST /revoke`, which wipes your data at once. You can also revoke at https://account.meethue.com/apps.

## Not stored

Commands, tool results, light state and IP addresses. The per-IP sign-in limiter keeps its counters in memory only and loses them on restart.

## Not claimed

- No third-party audit, and no protection against a compromised Cloudflare account or Worker secrets.
- Whoever operates the Worker can read the stored Hue tokens and bridge keys. If that matters to you, run your own copy: [SELF-HOST.md](SELF-HOST.md).
