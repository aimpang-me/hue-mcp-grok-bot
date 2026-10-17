<p align="center"><img src="assets/logo.png" width="96" alt="Logo"></p>

# hue-mcp

A free, open-source MCP connector for Philips Hue lights. Add it to any MCP client that supports OAuth connectors, sign in with your own Hue account once, and your assistant can list and control your lights, rooms and scenes. It only ever reaches your own bridge.

Connector URL: `https://hue-mcp.openwiring.workers.dev/mcp` (setup steps: [docs/SETUP.md](docs/SETUP.md))

## Before you connect

**Not a Signify product.** This project is independent and is not made, endorsed or supported by Signify (Philips Hue). Philips Hue is a trademark of Signify Holding.

**Light-sensitivity warning.** Rapid flashing, strobing, or fast colour or brightness changes can trigger seizures in people with photosensitive epilepsy. Do not ask an assistant to flash or strobe lights if you or anyone nearby may be sensitive. The connector caps changes per light per minute, but that is not a safety guarantee.

**Privacy.** The connector stores your Hue sign-in tokens and a bridge access key so it can act for you, and keeps no log of your lights or commands. The full list and how long each item is kept: [docs/PRIVACY.md](docs/PRIVACY.md). You can revoke access at any time at https://account.meethue.com/apps.

The sign-in page shows these notices again before you reach Hue's login.

## Tools

| Tool | What it does |
|---|---|
| `list_rooms`, `list_lights`, `list_scenes` | Show rooms, lights and scenes with their current state |
| `set_light`, `set_room`, `dim_room` | Turn on or off, set brightness, colour or colour temperature, by name |
| `activate_scene` | Recall a scene by name, optionally within a room |
| `hue_api` | A raw CLIPv2 call on `resource/...` paths of your bridge, for zones, sensors and anything else. It can permanently delete scenes, automations and devices, so the assistant is told to confirm with you first. |

## Limitations

- Works with the Hue Bridge v2 (the square one, BSB002), not the round v1 bridge, and only with the first bridge on a Hue account.
- Needs internet: it reaches your bridge through Hue's cloud, not your local network.
- Hue's cloud allows a limited number of calls per day. The hosted connector allows 3,000 per bridge per day, 45,000 for all users together, and 20 changes per light, room or scene per minute. Daily limits reset at 00:00 UTC.
- At most 10 new sign-ins per bridge per day. A sign-in lasts up to 180 days, then you sign in again.
- No Entertainment (light streaming) support.
- Free and best effort, with no uptime promise. The hosted connector uses one shared Hue developer app. If that access ever stops, you can run your own copy with your own app: [docs/SELF-HOST.md](docs/SELF-HOST.md).

## More

- [docs/DESIGN.md](docs/DESIGN.md): how it works and its security model
- [docs/SELF-HOST.md](docs/SELF-HOST.md): run your own copy, and every setting
- [docs/DEVELOPING.md](docs/DEVELOPING.md): tests, type checks, local runs

License: MIT, see [LICENSE](LICENSE).
