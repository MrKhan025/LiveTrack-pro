'use strict';

const crypto = require('crypto');
const EventEmitter = require('events');

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

class NativeWebSocketClient extends EventEmitter {
  constructor(socket) {
    super();
    this.socket = socket;
    this.readyState = 1; // OPEN
    this.meta = {};
    this._buffer = Buffer.alloc(0);

    socket.on('data', (chunk) => this._onData(chunk));
    socket.on('close', () => {
      this.readyState = 3;
      this.emit('close');
    });
    socket.on('error', () => {
      this.readyState = 3;
      this.emit('close');
    });
  }

  _onData(chunk) {
    this._buffer = Buffer.concat([this._buffer, chunk]);
    while (this._buffer.length >= 2) {
      const firstByte = this._buffer[0];
      const secondByte = this._buffer[1];
      const opcode = firstByte & 0x0f;
      const isMasked = (secondByte & 0x80) !== 0;
      let payloadLen = secondByte & 0x7f;
      let offset = 2;

      if (payloadLen === 126) {
        if (this._buffer.length < 4) return;
        payloadLen = this._buffer.readUInt16BE(2);
        offset = 4;
      } else if (payloadLen === 127) {
        if (this._buffer.length < 10) return;
        payloadLen = Number(this._buffer.readBigUInt64BE(2));
        offset = 10;
      }

      const maskLength = isMasked ? 4 : 0;
      if (this._buffer.length < offset + maskLength + payloadLen) return;

      let payload = this._buffer.subarray(offset + maskLength, offset + maskLength + payloadLen);
      if (isMasked) {
        const mask = this._buffer.subarray(offset, offset + 4);
        const unmasked = Buffer.alloc(payloadLen);
        for (let i = 0; i < payloadLen; i++) {
          unmasked[i] = payload[i] ^ mask[i % 4];
        }
        payload = unmasked;
      }

      this._buffer = this._buffer.subarray(offset + maskLength + payloadLen);

      if (opcode === 0x8) {
        // Close frame
        this.close();
        return;
      } else if (opcode === 0x9) {
        // Ping -> Pong
        this._sendFrame(payload, 0xA);
      } else if (opcode === 0x1 || opcode === 0x2) {
        this.emit('message', payload.toString('utf8'));
      }
    }
  }

  _sendFrame(dataBuffer, opcode = 0x1) {
    if (this.readyState !== 1 || this.socket.destroyed || !this.socket.writable) return;
    const len = dataBuffer.length;
    let header;
    if (len < 126) {
      header = Buffer.alloc(2);
      header[0] = 0x80 | opcode;
      header[1] = len;
    } else if (len < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x80 | opcode;
      header[1] = 126;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x80 | opcode;
      header[1] = 127;
      header.writeBigUInt64BE(BigInt(len), 2);
    }
    try {
      this.socket.write(Buffer.concat([header, dataBuffer]));
    } catch {
      this.readyState = 3;
    }
  }

  send(data) {
    const str = typeof data === 'string' ? data : JSON.stringify(data);
    this._sendFrame(Buffer.from(str, 'utf8'), 0x1);
  }

  close() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    try {
      const closeFrame = Buffer.from([0x88, 0x00]);
      this.socket.write(closeFrame);
      this.socket.end();
    } catch {}
    this.emit('close');
  }
}

class UnifiedWebSocketServer extends EventEmitter {
  constructor(httpServer, pathPrefix = '/ws') {
    super();
    this.clients = new Set();
    this.pathPrefix = pathPrefix;

    httpServer.on('upgrade', (req, socket, head) => {
      if (!req.url || !req.url.startsWith(this.pathPrefix)) {
        socket.destroy();
        return;
      }
      const key = req.headers['sec-websocket-key'];
      if (!key) {
        socket.destroy();
        return;
      }
      const acceptKey = crypto
        .createHash('sha1')
        .update(key + WS_GUID)
        .digest('base64');

      const responseHeaders = [
        'HTTP/1.1 101 Switching Protocols',
        'Upgrade: websocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Accept: ${acceptKey}`,
        '',
        ''
      ].join('\r\n');

      socket.write(responseHeaders);
      const client = new NativeWebSocketClient(socket);
      this.clients.add(client);
      client.on('close', () => this.clients.delete(client));
      this.emit('connection', client, req);
    });
  }

  broadcastToOwner(ownerId, payload) {
    const message = typeof payload === 'string' ? payload : JSON.stringify(payload);
    for (const client of this.clients) {
      if (client.readyState === 1 && (client.meta.userId === ownerId || client.meta.role === 'admin')) {
        client.send(message);
      }
    }
  }
}

module.exports = { UnifiedWebSocketServer };
