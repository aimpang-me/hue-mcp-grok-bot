# Design and security model

A Hue bridge only talks outbound to Philips' cloud (the Hue Remote API at `api.meethue.com`). It cannot be pointed at a custom relay and must not be port-forwarded, so a hosted connector has to go through that cloud API. This connector is a Cloudflare Worker that does exactly that, for many users at once.

## Components

- `worker/index.js` wires the route table. Each route is in `worker/routes/`: `discovery` (RFC 9728 and RFC 8414 metadata), `register` (RFC 7591 client registration), `authorize` (consent page and approval), `callback` (Hue sends the user back here), `token`, `revoke` (RFC 7009, which is also the user's disconnect) and `mcp`.
- `worker/user-do.js` is a Durable Object class. Each user gets one instance, named by a random 128-bit id, which holds that user's Hue tokens, bridge key and the hashes of their MCP codes and tokens. The same class also runs one `bridge:<sha256 of bridge id>` instance per bridge (`worker/do/registry.js`) and one `global` instance for the shared quota. Neither holds user data. `worker/do-client.js` lists every operation with its arguments and result.
- `server/tools.js` is the tool layer, shared with the local stdio server. It talks to a transport `(method, path, body) => { status, text }`: `server/transport-remote.js` for the Hue cloud, or `server/transport-local.js` on a LAN for testing.
- No KV or database. The login itself stores nothing until a Hue sign-in succeeds.

## Sign-in

1. The MCP client calls `/mcp`, gets a 401 that points at the metadata, registers itself at `/register` and opens `/authorize` in the user's browser.
2. `GET /authorize` checks the request and shows the consent page. The page leads with where the result will go (the redirect host, or "an app on this device" for an app-scheme URI) and shows the client's self-chosen name labelled as a claim, because anyone can register any name. Until the user approves, nothing is ever redirected to the client. A bad request gets an error page instead.
3. The page sets a `hue_consent` cookie (HttpOnly, SameSite=Strict, Path=/authorize, 10 minutes). Approving is a `POST /authorize` carrying a token whose MAC covers that cookie and the exact request. So only the browser that saw the page can approve it, and the page cannot be re-pointed at another client or redirect URI.
4. The approving POST sets `hue_login` (HttpOnly, SameSite=Lax, Path=/oauth/callback, 10 minutes). It is a signed copy of the request plus a random nonce, which is also the `state` sent to Hue. Then it redirects to Hue's own login. This connector never sees the Hue password.
5. `/oauth/callback` accepts only a genuine, unexpired `hue_login` cookie whose nonce matches `state`, so another browser cannot finish someone's login. It exchanges the Hue code, creates a new user id, links the bridge (below), mints a one-time MCP code and sends the browser back to the client. Hue codes are single use, so replaying a callback creates nobody.
6. The client redeems the code at `/token` with its PKCE verifier.

## Tokens

- Codes and tokens look like `<uid>.<tag>.<secret>`. `tag` is an HMAC of the uid under `SIGNING_SECRET`, checked in the Worker before any Durable Object is addressed. A forged id therefore never creates an instance. Only `sha256(token)` is stored.
- A code lives 10 minutes and works once. It is bound to the client, the redirect URI and the PKCE challenge. If the client sent `redirect_uri` at `/authorize` it must send the same one at `/token`; if it left it out there (allowed with one registered URI), it may leave it out here. Presenting a used code again revokes everything issued from it.
- Access tokens live 1 hour. Refresh tokens live 30 days, rotate on every use, and are bound to their client. Reusing an old refresh token revokes the whole sign-in. No token outlives 180 days after the sign-in, however often it is refreshed.
- Every code and token is bound to this server's `/mcp` (RFC 8707), so a token cannot be replayed at another resource or origin.
- Disconnecting needs a live, unrevoked token. Afterwards the user's instance keeps a `disabled` flag: Hue calls answer 401, and a Hue token refresh that was still in flight cannot write tokens back.

## Isolation

A token leads to one uid, and that uid to one Durable Object, which checks the token hash itself. Hue tokens, the bridge key and light ids never leave that object. Name-to-id caches in the Worker are kept per uid. Every Hue call is checked twice to be `GET`, `PUT`, `POST` or `DELETE` on `/resource`, `/resource/<type>` or `/resource/<type>/<id>`: by the `hue_api` tool and again inside the Durable Object. Hue error text is scrubbed of the user's bridge key and Hue tokens before it leaves the object.

## Bridge keys

A bridge holds about 40 app keys, so sign-ins on one bridge share one key:

- The cloud's config call names the bridge. If it does not, the connector pairs a key, reads the bridge id from CLIPv2 and continues. A bridge that cannot be identified at all is refused, because every sign-in has to count against its bridge's limits. Any key a sign-in pairs and does not end up storing is removed from the bridge again, on every path including errors.
- A sign-in claims a slot in the bridge's registry, which counts it against 10 sign-ins per bridge per day and gives it a 10-minute lease. The lease becomes a permanent holder once the user record is written, or expires on its own if the sign-in dies halfway.
- A stored key is reused if it still works. Otherwise the sign-in presses the bridge's virtual link button through the cloud and stores the new key with compare-and-set. If two first sign-ins race, the second one removes its own new key from the bridge and uses the stored one, so no key is left behind.
- Disconnecting releases the holder. When nobody else holds the key, it is removed from the bridge, but only if the account's first bridge is still the one it was paired with. A reordered account never loses a key on the wrong bridge.
- Only the account's first bridge (`/bridge/0`) is used. There is no bridge picker.

## Budgets and limits

| Limit | Default | Setting |
|---|---|---|
| Hue calls per bridge per day (shared by every sign-in on it) | 3,000 | `DAILY_HUE_CALLS` |
| Hue calls per day for all users together (Hue allows 50,000) | 45,000 | `GLOBAL_DAILY_CALLS` |
| New sign-ins pause at | 90% of the global budget | |
| Changes per light, room or scene per minute | 20 | `LIGHT_CAP_PER_MIN` |
| MCP requests per sign-in per minute | 60 | `RATE_PER_MIN` |
| New sign-ins per bridge per day | 10 | `BRIDGE_LOGINS_PER_DAY` |
| Per client IP per minute: approving consent, `/register`, `/token`, `/revoke` | 10, 20, 60, 30 | `AUTHORIZE_PER_MIN`, `REGISTER_PER_MIN`, `TOKEN_PER_MIN`, `REVOKE_PER_MIN` |

A call that a user's own limits refuse never touches the shared budget. Each bridge reserves the shared budget in blocks of 10 calls, so the `global` instance sees one request per block. Whether new sign-ins are welcome is asked of it at most once a minute per Worker isolate. Request bodies are capped at 64 KB and are read no further than that.

## Cleanup

Every Durable Object keeps one alarm at its earliest expiry. The alarm deletes expired codes, tokens, reuse markers and leases, and per-day counters two days after their date. When a user has no live code or token left (never redeemed, or 30 days unused), the alarm runs the same path as a disconnect.

## Known limits

- Per-IP limits live in each Worker isolate's memory, so they are not global and reset on restart. They slow bursts down. The daily caps in Durable Objects are the hard bounds. The per-minute windows inside a Durable Object also reset when it is evicted, which allows at most one extra burst.
- App-scheme redirect URIs (for example `cursor://...`) can be claimed by any app installed on the same device, which could then receive the authorization code. PKCE stops that app from redeeming the code without the verifier, and the consent page warns about app links. Approve only sign-ins you started.
- `hue_api` can change and permanently delete resources on your bridge. Its description tells the assistant to confirm first; the connector does not block it.
- If the Worker cannot reach the registry while you disconnect, your data is still wiped, but the shared key stays registered until a later release.
- Unused blocks of reserved quota lapse at the end of the day, at most 9 calls per active bridge.
- Some Remote API calls (reading the bridge id, removing a key) follow Hue's published API and have had limited testing against the live service.
