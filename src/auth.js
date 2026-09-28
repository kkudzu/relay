import { createHmac, timingSafeEqual } from "node:crypto";
import { parseTarget } from "./protocol.js";

function base64url(input) {
  return Buffer.from(input).toString("base64url");
}

function signPayload(secret, payload) {
  if (!secret || secret.length < 16) throw new Error("RELAY_SECRET must be at least 16 characters");
  const encoded = base64url(JSON.stringify(payload));
  const signature = createHmac("sha256", secret).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

function verifyPayload(secret, token, nowSeconds) {
  if (!secret || !token) throw new Error("missing relay authentication");
  const pieces = token.split(".");
  if (pieces.length !== 2) throw new Error("malformed relay token");
  const expected = createHmac("sha256", secret).update(pieces[0]).digest();
  const actual = Buffer.from(pieces[1], "base64url");
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    throw new Error("invalid relay token");
  }
  let payload;
  try {
    payload = JSON.parse(Buffer.from(pieces[0], "base64url").toString("utf8"));
  } catch {
    throw new Error("malformed relay token payload");
  }
  if (payload.v !== 1 || !Number.isInteger(payload.exp) || payload.exp < nowSeconds) {
    throw new Error("expired relay token");
  }
  return payload;
}

export function createToken(secret, target, ttlSeconds = 3600, nowSeconds = Math.floor(Date.now() / 1000)) {
  const canonical = parseTarget(target).canonical;
  return signPayload(secret, { v: 1, target: canonical, exp: nowSeconds + ttlSeconds });
}

export function verifyToken(secret, token, target, nowSeconds = Math.floor(Date.now() / 1000)) {
  const payload = verifyPayload(secret, token, nowSeconds);
  const canonical = parseTarget(target).canonical;
  if (payload.target !== canonical) {
    throw new Error("expired or wrong-target relay token");
  }
  return payload;
}

export function createScopedToken(secret, scope, ttlSeconds = 21600, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (!scope || typeof scope !== "string") throw new Error("relay scope is required");
  return signPayload(secret, { v: 1, scope, exp: nowSeconds + ttlSeconds });
}

export function verifyScopedToken(secret, token, scope, nowSeconds = Math.floor(Date.now() / 1000)) {
  const payload = verifyPayload(secret, token, nowSeconds);
  if (payload.scope !== scope) throw new Error("expired or wrong-scope relay token");
  return payload;
}
