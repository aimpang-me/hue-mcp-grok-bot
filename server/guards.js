/** @param {unknown} v @returns {v is Record<string, unknown>} */
export const isRecord = (v) => typeof v === "object" && v !== null && !Array.isArray(v);

/** The only CLIPv2 paths this connector ever calls: `/resource`, `/resource/<type>` or `/resource/<type>/<id>`.
 * Checked by the hue_api tool and again inside the user's Durable Object. Groups: 1 = type, 2 = id. */
export const RESOURCE_PATH = /^\/resource(?:\/([a-z_]+)(?:\/([0-9a-z-]{8,64}))?)?$/;
/** The only methods hue_api and the Durable Object forward. */
export const METHODS = ["GET", "PUT", "POST", "DELETE"];
