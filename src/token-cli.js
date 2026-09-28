import { createScopedToken, createToken } from "./auth.js";

const target = process.argv[2];
const ttl = Number(process.argv[3] ?? 3600);
if (!target) {
  console.error("Usage: RELAY_SECRET=... npm run token -- host:port [ttlSeconds]");
  console.error("   or: RELAY_SECRET=... npm run token -- --lan-host [ttlSeconds]");
  process.exit(2);
}
if (target === "--lan-host") {
  console.log(createScopedToken(process.env.RELAY_SECRET, "lan-host", Number(process.argv[3] ?? 21600)));
} else {
  console.log(createToken(process.env.RELAY_SECRET, target, ttl));
}
