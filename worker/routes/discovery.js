// RFC 9728 protected-resource metadata and RFC 8414 authorization-server metadata.
import { json } from "../http.js";

/** @param {import("../index.js").Ctx} c */
export const protectedResource = ({ origin }) =>
  json({ resource: `${origin}/mcp`, authorization_servers: [origin], bearer_methods_supported: ["header"], resource_name: "Lights (free, open source, for Philips Hue)" });

/** @param {import("../index.js").Ctx} c */
export const authServer = ({ origin }) =>
  json({ issuer: origin, authorization_endpoint: `${origin}/authorize`, token_endpoint: `${origin}/token`, revocation_endpoint: `${origin}/revoke`, registration_endpoint: `${origin}/register`,
    response_types_supported: ["code"], grant_types_supported: ["authorization_code", "refresh_token"], code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"], revocation_endpoint_auth_methods_supported: ["none"], scopes_supported: ["hue"] });
