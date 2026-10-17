# Developing

## Tests and checks

- `npm test` runs the test suite with Node's built-in runner. No install is needed.
- `npm install` then `npm run typecheck` checks the JSDoc types with TypeScript (dev dependencies only; the connector has no runtime dependencies).
- The leak scan test (`test/leakscan.test.js`) refuses local paths, emails, long hex strings, LAN IPs and token-shaped text in any file that would ship. For words specific to you, such as your name, handles or private tool names, create `.leakscan.local` (gitignored) with one case-insensitive regular expression per line.

## End-to-end run on the Workers runtime

`WRANGLER=<path to wrangler> ./scripts/e2e-wrangler.sh` runs the Worker under `wrangler dev` against `scripts/mock-cloud.mjs`, a local stand-in for Hue's cloud, with dummy secrets in a temporary folder. It signs in two users, checks isolation, disconnect and code reuse, and checks that no mock key or token reaches the Worker log. `HUE_CLOUD_BASE` is honoured only for loopback http URLs, so it can never send real tokens anywhere but Philips.

## Local stdio server (LAN, testing only)

The hosted connector never uses this. It talks to a bridge on your own network directly.

1. Pair once: `node scripts/pair.mjs <bridge-ip>`, then press the round link button on the bridge within 60 seconds. The new key prints only to your terminal. On Windows, `--set-env` saves `HUE_BRIDGE_IP` and `HUE_APP_KEY` as user environment variables instead of printing the key.
2. Run: `HUE_BRIDGE_IP=<ip> HUE_APP_KEY=<key> node server/index.js` (an MCP server on stdio).

The bridge serves a self-signed certificate, so TLS verification is turned off for requests to that one bridge host only. Someone on the same network could intercept the key, so use this only on a network you trust.
