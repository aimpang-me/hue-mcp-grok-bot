# Setup guide

You need a Hue Bridge v2 (the square one, model BSB002) set up in the Hue app, and a Hue account with that bridge on it.

## Add the connector

1. In your MCP client (any client that supports OAuth connectors, such as an AI assistant app), add a custom connector with this URL:
   `https://hue-mcp.openwiring.workers.dev/mcp`
2. Your client opens a page from this connector. It shows where the result will be sent (check that this is the app you are using), the name the app gave itself (any app can claim any name), and the notices: not a Signify product, the light-sensitivity warning, and privacy. Read them and press **I understand, continue to Hue sign-in**. Nothing is approved until you press that button.
3. You are sent to Hue's own sign-in page. Sign in with your Hue account and grant access. This connector never sees your Hue password.
4. The connector links to your bridge once through Hue's cloud, with no button press on the bridge. This creates one access key on your bridge (shared with any other sign-in on the same bridge), which is removed when the last one disconnects.
5. You return to your client, and the connector is ready.

## Example prompts

- "List my rooms and lights."
- "Dim the kitchen to 20%."
- "Turn the living room lights off."
- "Set the desk lamp to warm white at 60% brightness."
- "Make the bedroom light a soft blue."
- "What scenes does the living room have? Activate Relax."

Avoid asking for flashing or strobing effects (see the light-sensitivity warning in the README).

## Disconnect

- Remove the connector in your MCP client. Clients that support token revocation then call the connector's `/revoke`, which deletes your data at once. Otherwise it is deleted after 30 days without use.
- Or remove this connector's access at https://account.meethue.com/apps.
- What is stored and for how long: [PRIVACY.md](PRIVACY.md).

## Troubleshooting

- "Daily budget used up" or "at capacity": Hue's cloud allows a limited number of calls per day. Try again after 00:00 UTC. The limits are in the README.
- "Too many sign-ins for this bridge today": at most 10 new sign-ins per bridge per day.
- Lights do not respond: the bridge needs internet access, because this connector reaches it through Hue's cloud.
- After 180 days you are asked to sign in again. That is expected.
