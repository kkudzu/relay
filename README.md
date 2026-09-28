# 26.2 Relay

A WebSocket relay for Eaglercraft 26.2, made by o_xer.

It handles two jobs:

- `/minecraft` forwards Minecraft Java traffic.
- `/` handles Eaglercraft 1.8 LAN signaling. The actual world traffic stays peer-to-peer over WebRTC.

## Run it on a VPS

You need Node.js 20 or newer.

```bash
git clone https://git.eymenwsmc.site/o_xer/26.2-relay.git
cd 26.2-relay
npm ci
RELAY_PUBLIC=1 npm start
```

The relay listens on port `8787` by default. Use `ws://host:8787` locally or put it behind HTTPS and connect with `wss://relay.example.com`.

To run it privately, set a secret:

```bash
RELAY_PUBLIC=0 RELAY_SECRET='use-a-long-random-secret' npm start
```

Create a token for a Minecraft server:

```bash
RELAY_SECRET="$RELAY_SECRET" npm run token -- server.example.com:25565 3600
```

Create a LAN host token:

```bash
RELAY_SECRET="$RELAY_SECRET" npm run token -- --lan-host 21600
```

Do not enable `RELAY_ALLOW_PRIVATE` on a public relay.

## Standalone client

The Node relay can serve the standalone client from `http://127.0.0.1:8787/`. This avoids browser restrictions that can block local relay connections when the HTML file is opened directly.

By default it looks for `../eaglercraft-26.2-single.html`. Set `RELAY_CLIENT_HTML` if the file is somewhere else:

```bash
RELAY_CLIENT_HTML=/absolute/path/to/client.html RELAY_PUBLIC=1 npm start
```

## Docker

```bash
docker build -t eagler-relay .
docker run --rm -p 8787:8787 -e RELAY_PUBLIC=1 eagler-relay
```

## Cloudflare Worker

The current public Worker is available at:

```text
wss://eagler-minecraft-relay.u2471966200.workers.dev
```

Add the base URL to the client's relay list and choose `Both`. The client uses `/minecraft` for Java servers and the root WebSocket for LAN signaling.

Deploy it with Wrangler:

```bash
npm ci
npx wrangler login
npm run deploy
```

For private mode, change `RELAY_PUBLIC` to `"0"` in `cloudflare/wrangler.toml`, store the secret, and deploy again:

```bash
npx wrangler secret put RELAY_SECRET --config cloudflare/wrangler.toml
npm run deploy
```

## Settings

- `RELAY_ALLOWED_ORIGINS` — comma-separated browser origins
- `RELAY_MAX_BYTES_PER_MINUTE` — byte limit for each connection
- `RELAY_MAX_LIFETIME_MS` — optional connection lifetime; `0` disables it
- `RELAY_MAX_LAN_PEERS` — maximum guests in a LAN room
- `RELAY_ICE_SERVERS` — comma-separated STUN or TURN servers; add `;username;password` for TURN
- `RELAY_LAN_UPSTREAM` — Eaglercraft 1.8 signaling relay endpoint
- `RELAY_ALLOW_PRIVATE` — allows private TCP targets on a trusted local relay
- `RELAY_CLIENT_HTML` — standalone client file served by the Node relay

## Checks

```bash
npm audit --omit=dev
npm test
npx wrangler deploy --dry-run --config cloudflare/wrangler.toml
```

## License

MIT. You can use, change, and redistribute the code as long as the copyright and license notice stay with it.
