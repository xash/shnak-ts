import { encode, decode } from 'debif-ts';
import { equalBuffer } from './helper';
import { hash, verify, SymKey, Identity, PrivKey, symEncrypt, randomBytes, symDecrypt, deriveKey, sharedSecret, PubKey } from './crypto';

export type MessageFilter = [string, string, any];

export function matchesFilters(msg: any, filters?: Array<MessageFilter>): boolean {
  if (!filters) return true;
  for (const [key, cmp, value] of filters) {
    if (!(key in msg)) return false;
    const x = msg[key];
    const y = value;
    switch (cmp) {
      case "=": {
        if (!
          (
            (typeof x === 'number' && typeof y === 'number' && x == y) ||
            (x instanceof Uint8Array && y instanceof Uint8Array && equalBuffer(x, y))
          )) return false; break;
      }
      case "<": {
        if (!(typeof x === 'number' && typeof y === 'number' && x < y))
          return false; break;
      }
      case ">": {
        if (!(typeof x === 'number' && typeof y === 'number' && x > y))
          return false; break;
      }
      case "<=": {
        if (!(typeof x === 'number' && typeof y === 'number' && x <= y))
          return false; break;
      }
      case ">=": {
        if (!(typeof x === 'number' && typeof y === 'number' && x >= y))
          return false; break;
      }
    }
  }
  return true;
}

export type Key = Uint8Array;
export type Hash = Uint8Array;
export type Certificate = [
  Key, number, Array<MessageFilter>
];

export type MessageCallback = (msg: Object, sender?: PubKey, hash?: Hash, receiver?: PubKey) => void;

export class Channel extends EventTarget {
  filters: Array<MessageFilter>;
  seen: Set<string>;

  constructor(filters?: Array<MessageFilter>) {
    super();
    this.seen = new Set();
    this.filters = filters;
  }

  broadcast(msg: Object, sender?: PubKey, hash?: Hash, receiver?: PubKey): boolean {
    if (this.seen.has(hash.join(','))) return false;
    if (!matchesFilters(msg, this.filters)) return false;
    this.seen.add(hash.join(','));
    this.dispatchEvent(new CustomEvent('msg',
      { detail: { msg, sender, hash, receiver } }));
    return true;
  }
};

export class Shnaker extends EventTarget {
  socket: WebSocket;
  id: Identity;
  msgBuf: ArrayBuffer;
  channels: Array<Channel>;
  idMap: Map<string, { rs: number, certs: Array<Certificate> }>;
  mappedToOrig: Map<string, [Key, Certificate]>;
  connected: boolean;

  constructor(socket: any, signer: Identity) {
    super();
    this.connected = false;
    this.id = signer;
    this.msgBuf = new ArrayBuffer(1 << 16);
    this.channels = [];
    this.idMap = new Map();
    this.mappedToOrig = new Map();
    const shnaker = this;

    this.socket = socket;
    this.socket.addEventListener('error', (err) => {
      shnaker.connected = false;
      shnaker.dispatchEvent(new Event('close'));
    });
    this.socket.addEventListener('close', (_) => {
      shnaker.connected = false;
      shnaker.dispatchEvent(new Event('close'));
    });
    this.socket.addEventListener('open', (_) => {
      shnaker.connected = true;
      shnaker.dispatchEvent(new Event("open"));
    });
    this.socket.addEventListener('message', (event) => shnaker.handleMessage(event));
    this.socket.binaryType = "arraybuffer";
  }

  /* TODO
  private handleIdentityUpdate(msg: { I: number, certs: Array<Certificate> }, sender: Key) {
    const prevEntry = this.idMap.get(sender.join(','));
    if (!prevEntry) {
      this.idMap.set(sender.join(','), { rs: msg.I, certs: msg.certs });
      for (const cert of msg.certs) {
        const [key, status, filter] = cert;
        this.mappedToOrig.set(key.join(','), [sender, cert]);
      }
    } else if (prevEntry.rs < msg.I) {
      for (const [key, status, filter] of prevEntry.certs) {
        this.mappedToOrig.delete(key.join(','));
      }
      this.idMap.set(sender.join(','), { rs: msg.I, certs: msg.certs });
      for (const cert of msg.certs) {
        const [key, status, filter] = cert;
        this.mappedToOrig.set(key.join(','), [sender, cert]);
      }
    }
  }
  */

  private handleMessage(event: MessageEvent) {
    const data = event.data instanceof ArrayBuffer ? new Uint8Array(event.data) : event.data;
    const msg: any = decode(data);
    if (msg.K === undefined) throw new Error("malformed");
    switch (msg.K) {
      /* PUBLISH */
      case -4: {
        /* validate message */
        if (msg.m === undefined) throw new Error("malformed");
        if (msg.p === undefined) throw new Error("malformed");
        const h = hash(msg.p, msg.m);
        if (msg.s === undefined || verify(msg.s, msg.p, h)) throw new Error("malformed");

        type KindType = { K: number, R: Uint8Array };
        var s = decode(msg.m);
        const sKind = s as KindType;

        /* handle ID map */
        /*
        if (sKind.K && sKind.K == 100) {
          type IdMapMsg = { I: number, certs: Array<Certificate> };
          this.handleIdentityUpdate(s as IdMapMsg, msg.p);
        }
        */

        /* handle encrypted message */
        /*
        if (sKind.K && sKind.K == 2) {
          type EncryptedSimple = { R: Uint8Array, d: Uint8Array, iv: Uint8Array };
          const sEncryptedSimple = s as EncryptedSimple;
          if (equalBuffer(sEncryptedSimple.R, this.id.pub)) {
            try {
              const decrypted = this.identities.decrypt(msg.p, sEncryptedSimple.d, sEncryptedSimple.iv);
              s = decode(decrypted);
            } catch (e) {
              //console.log("error decrypting", e, sEncryptedSimple.d);
              return;
            }
          }
        }
        */

        for (const channel of this.channels)
          channel.broadcast(s, new PubKey(msg.p), h, sKind.R ? new PubKey(sKind.R) : undefined);
        break;
      }
    }
  }

  subscribe(filters?: Array<MessageFilter>): Channel {
    const msg = {
      K: -2,
      c: 0,
    };
    const buf = encode(this.msgBuf, msg);
    const channel = new Channel(filters);
    this.channels.push(channel);
    if (this.connected) {
      this.socket.send(buf);
    } else {
      this.addEventListener('open', (_) => {
        this.socket.send(buf);
      }, { once: true });
    }
    return channel;
  }

  publishPublicAs(obj: Object, signer: Identity) {
    const toPublish = new Uint8Array(encode(this.msgBuf, obj));
    const h = hash(signer.pub.pubBytes, toPublish);
    const sig = signer.sign(h);
    const msg = {
      K: -4,
      m: toPublish,
      s: sig,
      p: signer.pub.pubBytes,
    };
    const buf = encode(this.msgBuf, msg)
    this.socket.send(buf);
  }

  publishPublic(obj: Object) {
    return this.publishPublicAs(obj, this.id);
  }

  initGroup(members: Array<{ key: PubKey, write: boolean, read: boolean }>, iteration: number) {
    const innerGroupKey = new Identity(randomBytes(32));
    for (const { key, write, read } of members) {
      const secret = sharedSecret(this.id.priv, key);
      const sharedChannel = deriveKey(secret, undefined, "groupChannel", 32);
      const sharedSymKey = deriveKey(secret, undefined, "groupChannelEnc", 32);
      const sharedId = new Identity(sharedChannel);
      const payload = symEncrypt(new SymKey(sharedSymKey), encode(this.msgBuf, {
        K: 101,
        I: iteration,
        priv: read ? innerGroupKey.priv.privBytes : null,
        pub: write ? innerGroupKey.pub.pubBytes : null,
        members: members.map(x => x.key.pubBytes),
      }));
      this.publishPublicAs({
        K: 2,
        d: payload
      }, sharedId);
    }
  }

  announce(certificates: Array<Certificate>, iteration: number) {
    this.publishPublic({
      K: 100,
      I: iteration,
      certs: certificates,
    })
  }
}
