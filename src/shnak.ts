import { encode, decode } from 'debif-ts';
import { hash, verify, Signer } from './crypto';

export class Shnaker extends EventTarget {
  ws: WebSocket;
  signer: Signer;
  msgBuf: ArrayBuffer;
  publishI: number;
  handlers: Array<any>;

  constructor(socket: any, signer: Signer) {
    super();
    this.ws = socket;
    this.ws.onerror = (err) => { console.error(err); this.error(); };
    this.ws.onclose = (_) => this.close();
    this.ws.onopen = (_) => this.dispatchEvent(new Event("open"));
    this.ws.onmessage = (event) => this.handleMessage(event);

    this.ws.binaryType = "arraybuffer";
    this.signer = signer;
    this.msgBuf = new ArrayBuffer(1 << 16);
    this.publishI = 0;
    this.handlers = [];
  }

  close() {
    console.log("closed");
    this.ws.close();
    this.dispatchEvent(new Event('close'));
  }

  private handleMessage(event: MessageEvent) {
    if (!(event.data instanceof ArrayBuffer)) throw new Error("error");
    const msg: any = decode(event.data);
    if (msg.K === undefined) throw new Error("malformed");
    switch (msg.K) {
      case -4: {
        if (msg.m === undefined) throw new Error("malformed");
        if (msg.p === undefined) throw new Error("malformed");
        const h = hash(msg.p, msg.m);
        if (msg.s === undefined || verify(msg.s, msg.p, h)) throw new Error("malformed");
        const s = decode(msg.m.buffer);
        for (const callback of this.handlers) {
          callback(s);
        }
        break;
      }
    }
  }

  private error() {
    console.log("errd");
    // this.dispatchEvent(new Event("error"));
  }

  subscribe(callback) {
    const msg = {
      K: -2,
      c: 0,
    };
    const buf = encode(this.msgBuf, msg);
    this.handlers.push(callback);
    this.ws.send(buf);
  }

  publish(obj: Object) {
    const toPublish = new Uint8Array(encode(this.msgBuf, obj));
    const h = hash(this.signer.pub, toPublish);
    const sig = this.signer.sign(h);
    const msg = {
      K: -4,
      i: this.publishI++,
      m: toPublish,
      s: sig,
      p: this.signer.pub,
    };
    const buf = encode(this.msgBuf, msg)
    this.ws.send(buf);
  }
}
