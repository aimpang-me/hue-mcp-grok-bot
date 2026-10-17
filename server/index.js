#!/usr/bin/env node
// Config comes ONLY from env: HUE_BRIDGE_IP and HUE_APP_KEY. The key is never logged or echoed.
import { createHue } from "./transport-local.js";
import { createHandler, serve } from "./rpc.js";
import { createTools } from "./tools.js";

const ip = process.env.HUE_BRIDGE_IP;
const key = process.env.HUE_APP_KEY;
if (!ip || !key) {
  process.stderr.write("hue-mcp: set HUE_BRIDGE_IP and HUE_APP_KEY (see docs/DEVELOPING.md).\n");
  process.exit(1);
}
serve(createHandler(createTools(createHue({ ip, key }), { key })));
