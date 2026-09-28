const MAX_HOST_BYTES = 255;

export async function normalizeBinaryData(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (data && typeof data === "object" && typeof data.byteLength === "number") {
    if (data.buffer && typeof data.byteOffset === "number") {
      return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    }
    try {
      return new Uint8Array(data);
    } catch {}
  }
  if (data && typeof data.arrayBuffer === "function") {
    return new Uint8Array(await data.arrayBuffer());
  }
  return null;
}

export function parseTarget(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 320) {
    throw new Error("invalid target");
  }
  value = value.trim();
  let host;
  let portText;
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    if (end < 2 || (end + 1 < value.length && value[end + 1] !== ":")) {
      throw new Error("IPv6 targets must use [host] or [host]:port");
    }
    host = value.slice(1, end);
    portText = end + 1 === value.length ? "25565" : value.slice(end + 2);
  } else {
    const split = value.lastIndexOf(":");
    if (split === -1) {
      host = value;
      portText = "25565";
    } else {
      if (split <= 0 || value.indexOf(":") !== split) {
        throw new Error("IPv6 targets must use [host] or [host]:port");
      }
      host = value.slice(0, split);
      portText = value.slice(split + 1);
    }
  }
  const port = Number(portText);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535 || port === 25) {
    throw new Error("invalid target port");
  }
  return { host, port, canonical: host.includes(":") ? `[${host}]:${port}` : `${host}:${port}` };
}

export function isPrivateTarget(host) {
  const lower = host.toLowerCase().replace(/\.$/, "");
  if (lower === "localhost" || lower.endsWith(".localhost") || lower.endsWith(".local")) {
    return true;
  }
  const ipv4 = lower.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const octets = ipv4.slice(1).map(Number);
    if (octets.some((n) => n > 255)) return true;
    const [a, b] = octets;
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19));
  }
  return lower === "::1" || lower === "::" || lower.startsWith("fc") ||
    lower.startsWith("fd") || lower.startsWith("fe8") || lower.startsWith("fe9") ||
    lower.startsWith("fea") || lower.startsWith("feb");
}

function readVarInt(bytes, offset) {
  let value = 0;
  for (let i = 0; i < 5; i++) {
    if (offset + i >= bytes.length) return null;
    const byte = bytes[offset + i];
    value |= (byte & 0x7f) << (7 * i);
    if ((byte & 0x80) === 0) return { value: value >>> 0, next: offset + i + 1 };
  }
  throw new Error("VarInt exceeds five bytes");
}

export function validateMinecraftHandshake(bytes) {
  if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
  let length;
  try {
    length = readVarInt(bytes, 0);
  } catch (error) {
    return { status: "invalid", reason: error.message };
  }
  if (!length) return { status: "more" };
  if (length.value < 6 || length.value > 65536) {
    return { status: "invalid", reason: "invalid handshake packet length" };
  }
  const packetEnd = length.next + length.value;
  if (bytes.length < packetEnd) return { status: "more" };
  try {
    let cursor = length.next;
    const packetId = readVarInt(bytes, cursor);
    if (!packetId || packetId.value !== 0) throw new Error("first packet is not handshake");
    cursor = packetId.next;
    const protocol = readVarInt(bytes, cursor);
    if (!protocol || protocol.value === 0) throw new Error("invalid protocol version");
    cursor = protocol.next;
    const hostLength = readVarInt(bytes, cursor);
    if (!hostLength || hostLength.value < 1 || hostLength.value > MAX_HOST_BYTES) {
      throw new Error("invalid handshake hostname");
    }
    cursor = hostLength.next;
    if (cursor + hostLength.value + 2 > packetEnd) throw new Error("truncated handshake hostname");
    const hostBytes = bytes.slice(cursor, cursor + hostLength.value);
    const handshakeHost = new TextDecoder("utf-8", { fatal: true }).decode(hostBytes);
    cursor += hostLength.value;
    const handshakePort = (bytes[cursor] << 8) | bytes[cursor + 1];
    cursor += 2;
    const nextState = readVarInt(bytes, cursor);
    if (!nextState || (nextState.value !== 1 && nextState.value !== 2) || nextState.next !== packetEnd) {
      throw new Error("invalid handshake next state");
    }
    return {
      status: "valid",
      packetEnd,
      protocol: protocol.value,
      nextState: nextState.value,
      host: handshakeHost,
      port: handshakePort
    };
  } catch (error) {
    return { status: "invalid", reason: error.message };
  }
}

export function concatBytes(chunks, total) {
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

export function encodeVarInt(value) {
  const bytes = [];
  do {
    let part = value & 0x7f;
    value >>>= 7;
    if (value !== 0) part |= 0x80;
    bytes.push(part);
  } while (value !== 0);
  return Uint8Array.from(bytes);
}

export function makeHandshake(host, port, protocol = 776, nextState = 2) {
  const hostBytes = new TextEncoder().encode(host);
  const bodyParts = [
    encodeVarInt(0),
    encodeVarInt(protocol),
    encodeVarInt(hostBytes.length),
    hostBytes,
    Uint8Array.of((port >>> 8) & 255, port & 255),
    encodeVarInt(nextState)
  ];
  const bodyLength = bodyParts.reduce((sum, part) => sum + part.length, 0);
  return concatBytes([encodeVarInt(bodyLength), ...bodyParts],
    encodeVarInt(bodyLength).length + bodyLength);
}
