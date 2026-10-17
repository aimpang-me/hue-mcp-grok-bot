// Which Durable Object records expire, and when. Pure, so the alarm sweep is easy to test and to reason about.
import { DAY } from "./limits.js";

/** Records that carry their own `exp` (ms epoch). */
const TIMED = /^(at|rt|code|used|grant|lease):/;
/** Per-UTC-day counters (bridge sign-ins, bridge calls, a bridge's reserved global quota, global calls): dead once the day is over,
 * kept one extra day for clock skew. */
const DAILY = /^(bl|bc|bq|gq):(\d{4}-\d\d-\d\d)$/;
/** Records that are only worth keeping while a sign-in could still use them. */
export const AUTH_RECORD = /^(at|rt|code):/;

/** When does this record stop mattering? null = lives until explicitly removed. @param {string} key @param {any} value @returns {number|null} */
export function expiryOf(key, value) {
  if (TIMED.test(key)) return typeof value?.exp === "number" ? value.exp : 0; // a timed record with no expiry is malformed: sweep it
  const d = DAILY.exec(key);
  return d ? Date.parse(d[2]) + 2 * DAY : null;
}
