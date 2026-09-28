import { randomBytes } from "node:crypto";

const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const HOST_FRAME_VERSION = 1;
const MAX_BUFFERED_BYTES = 8 * 1024 * 1024;

function randomCode(length) {
  const bytes = randomBytes(length);
  let code = "";
  for (let i = 0; i < bytes.length; ++i) {
    code += CODE_ALPHABET[bytes[i] % CODE_ALPHABET.length];
  }
  return code;
}

function sendJson(ws, value) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(value));
}

function closeSocket(ws, code, reason) {
  if (ws.readyState === ws.OPEN || ws.readyState === ws.CONNECTING) {
    ws.close(code, reason.slice(0, 120));
  }
}

function peerFrame(peerId, data) {
  const id = Buffer.from(peerId, "ascii");
  const payload = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const frame = Buffer.allocUnsafe(2 + id.length + payload.length);
  frame[0] = HOST_FRAME_VERSION;
  frame[1] = id.length;
  id.copy(frame, 2);
  payload.copy(frame, 2 + id.length);
  return frame;
}

function parseHostFrame(data) {
  const frame = Buffer.isBuffer(data) ? data : Buffer.from(data);
  if (frame.length < 3 || frame[0] !== HOST_FRAME_VERSION) {
    throw new Error("invalid LAN host frame");
  }
  const idLength = frame[1];
  if (idLength < 8 || idLength > 32 || frame.length < 2 + idLength) {
    throw new Error("invalid LAN peer id");
  }
  return {
    peerId: frame.subarray(2, 2 + idLength).toString("ascii"),
    payload: frame.subarray(2 + idLength)
  };
}

export class LanRoomRegistry {
  constructor(options = {}) {
    this.rooms = new Map();
    this.maxPeers = Number(options.maxPeers ?? 8);
    this.maxLifetimeMs = Number(options.maxLifetimeMs ?? 6 * 60 * 60 * 1000);
    this.maxBytesPerMinute = Number(options.maxBytesPerMinute ?? 512 * 1024 * 1024);
  }

  hasRoom(code) {
    return this.rooms.has(String(code ?? "").toUpperCase());
  }

  acceptHost(ws) {
    let code;
    do code = randomCode(6); while (this.rooms.has(code));
    const room = { code, host: ws, peers: new Map(), closed: false, timer: null };
    this.rooms.set(code, room);
    room.timer = setTimeout(() => this.closeRoom(room, 1000, "LAN room expired"), this.maxLifetimeMs);
    room.timer.unref?.();

    sendJson(ws, { type: "hosted", code, maxPeers: this.maxPeers });
    ws.on("message", (data, isBinary) => {
      if (!isBinary) return this.closeRoom(room, 1003, "binary host frames required");
      try {
        const { peerId, payload } = parseHostFrame(data);
        const peer = room.peers.get(peerId);
        if (!peer) return;
        if (!this.charge(peer, payload.byteLength)) return this.closePeer(room, peer, 1008, "rate limit exceeded");
        if (peer.ws.bufferedAmount > MAX_BUFFERED_BYTES) return this.closePeer(room, peer, 1008, "peer is too slow");
        if (peer.ws.readyState === peer.ws.OPEN && payload.length) peer.ws.send(payload, { binary: true });
      } catch (error) {
        this.closeRoom(room, 1008, error.message);
      }
    });
    ws.on("close", () => this.closeRoom(room, 1000, "LAN host disconnected"));
    ws.on("error", () => this.closeRoom(room, 1011, "LAN host failed"));
    return code;
  }

  acceptGuest(ws, code) {
    const room = this.rooms.get(String(code ?? "").toUpperCase());
    if (!room || room.closed || room.host.readyState !== room.host.OPEN) {
      closeSocket(ws, 1008, "LAN room is unavailable");
      return null;
    }
    if (room.peers.size >= this.maxPeers) {
      closeSocket(ws, 1013, "LAN room is full");
      return null;
    }

    let peerId;
    do peerId = randomBytes(8).toString("hex"); while (room.peers.has(peerId));
    const peer = { id: peerId, ws, windowStarted: Date.now(), windowBytes: 0, closed: false };
    room.peers.set(peerId, peer);
    sendJson(room.host, { type: "peer-open", peer: peerId });

    ws.on("message", (data, isBinary) => {
      if (!isBinary) return this.closePeer(room, peer, 1003, "binary frames required");
      if (!this.charge(peer, data.byteLength)) return this.closePeer(room, peer, 1008, "rate limit exceeded");
      if (room.host.bufferedAmount > MAX_BUFFERED_BYTES) return this.closePeer(room, peer, 1008, "host is too slow");
      if (room.host.readyState === room.host.OPEN) room.host.send(peerFrame(peerId, data), { binary: true });
    });
    ws.on("close", () => this.closePeer(room, peer, 1000, "guest disconnected"));
    ws.on("error", () => this.closePeer(room, peer, 1011, "guest failed"));
    return peerId;
  }

  charge(peer, bytes) {
    const now = Date.now();
    if (now - peer.windowStarted >= 60000) {
      peer.windowStarted = now;
      peer.windowBytes = 0;
    }
    peer.windowBytes += bytes;
    return peer.windowBytes <= this.maxBytesPerMinute;
  }

  closePeer(room, peer, code, reason) {
    if (peer.closed) return;
    peer.closed = true;
    room.peers.delete(peer.id);
    closeSocket(peer.ws, code, reason);
    sendJson(room.host, { type: "peer-close", peer: peer.id, reason });
  }

  closeRoom(room, code, reason) {
    if (room.closed) return;
    room.closed = true;
    clearTimeout(room.timer);
    this.rooms.delete(room.code);
    for (const peer of [...room.peers.values()]) {
      this.closePeer(room, peer, code, reason);
    }
    closeSocket(room.host, code, reason);
  }
}

export { parseHostFrame, peerFrame };
