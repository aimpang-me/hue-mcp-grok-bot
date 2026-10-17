// The consent page and the legal/safety notices that must be shown before the first Hue sign-in.
import { esc } from "./http.js";

export const NOTICES = {
  signify: "Not a Signify product. This free, open-source connector is independent and is not made, endorsed or supported by Signify (Philips Hue). Philips Hue is a trademark of Signify Holding.",
  safety: "Light-sensitivity warning: lighting changes (rapid flashing, strobing, colour or brightness changes) can trigger seizures in people with photosensitive epilepsy and can affect other health conditions. Do not ask an assistant to flash or strobe lights if you or anyone nearby may be sensitive.",
  privacy: "Privacy: you sign in with your own Hue account and this connector controls only your own lights. We store your Hue sign-in tokens, and a bridge key (an access key for your Hue Bridge, created on your bridge when you first connect and removed when you disconnect), to act for you, and keep no log or analytics of your lights or commands. Disconnect any time at account.meethue.com/apps.",
};
/** @param {string} client the name the client registered (unverified) @param {{ where: string, app: boolean }} to where the client will receive the result @param {[string, string][]} fields the authorize request plus the one-time consent token, posted back as hidden fields */
export const consentPage = (client, to, fields) => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect your lights</title>
<body style="font:16px system-ui;max-width:34em;margin:2em auto;padding:0 1em"><h1>Connect your lights</h1>
<p><b>${esc(to.where)}</b> wants to control <b>your</b> Philips Hue lights through this free connector. Only continue if you started this from that app.</p>
<p>Claimed app name: ${esc(client)}. Any app can register under any name, so trust the address above, not this name.${to.app ? " Links of this kind can be claimed by any app installed on your device." : ""} Next you will sign in to your Philips Hue account.</p>
<p>${esc(NOTICES.signify)}</p><p><b>${esc(NOTICES.safety)}</b></p><p>${esc(NOTICES.privacy)}</p>
<form method="post" action="/authorize">${fields.map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`).join("")}
<button type="submit" style="padding:.6em 1em;background:#222;color:#fff;border:0;border-radius:6px;font:inherit;cursor:pointer">I understand, continue to Hue sign-in</button></form></body>`;
/** Where a redirect URI returns, for the consent page: its host (https/loopback), or for an app link its scheme. @param {string} u @returns {{ where: string, app: boolean }} */
export const redirectLabel = (u) => {
  const p = new URL(u);
  return p.protocol.startsWith("http") ? { where: p.host, app: false } : { where: `an app on this device (${p.protocol} link)`, app: true };
};
