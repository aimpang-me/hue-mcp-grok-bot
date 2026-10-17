# Run your own copy

Use your own Hue developer app if you prefer not to rely on the shared one, or if it ever stops working. It is the same code, run for one user or a few. Your own app has its own 50,000 calls per day.

## Steps

1. Create a free Hue developer account and add a Remote Hue API app with the callback URL `https://<your-worker>/oauth/callback`. Note the AppId, ClientId and ClientSecret, and enter them only at the wrangler prompts below.
2. `cp wrangler.toml.example wrangler.toml`. The Durable Object binding and its migration are already in the template.
3. Set the secrets: `wrangler secret put HUE_APP_ID`, then the same for `HUE_CLIENT_ID`, `HUE_CLIENT_SECRET` and `SIGNING_SECRET`. For `SIGNING_SECRET`, use `openssl rand -hex 32`.
4. `wrangler deploy`, add `https://<your-worker>/mcp` as a connector in your MCP client, and complete the Hue sign-in once.
5. To stop anyone else signing in, set `SIGNUPS = "closed"` under `[vars]` in `wrangler.toml` and deploy again. Existing sign-ins keep working.

To try it locally without deploying, see [DEVELOPING.md](DEVELOPING.md).

## Settings

All optional, set under `[vars]` in `wrangler.toml`. A value that is not a positive number falls back to the default.

| Variable | Default | Meaning |
|---|---|---|
| `SIGNUPS` | open | `closed` refuses new sign-ins |
| `DAILY_HUE_CALLS` | 3000 | Hue calls per bridge per day |
| `GLOBAL_DAILY_CALLS` | 45000 | Hue calls per day for all users together |
| `LIGHT_CAP_PER_MIN` | 20 | Changes per light, room or scene per minute |
| `RATE_PER_MIN` | 60 | MCP requests per sign-in per minute |
| `BRIDGE_LOGINS_PER_DAY` | 10 | New sign-ins per bridge per day |
| `AUTHORIZE_PER_MIN` | 10 | Consent approvals per client IP per minute (viewing the page allows three times as many) |
| `REGISTER_PER_MIN` | 20 | Client registrations per client IP per minute |
| `TOKEN_PER_MIN` | 60 | Token requests per client IP per minute |
| `REVOKE_PER_MIN` | 30 | Revocations per client IP per minute |

The per-IP limits are counted in each Worker isolate's memory, not globally, and reset on restart. The daily caps are the hard bounds.

Users disconnect by removing the connector in their client (clients that support revocation call `POST /revoke`) or at https://account.meethue.com/apps.
