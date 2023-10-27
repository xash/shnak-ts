import { expect, test } from 'vitest'

import { Shnaker } from './shnaker';
import { Identity } from './crypto';

class MockConnection extends EventTarget {
  other?: MockConnection;
  sent: number;

  constructor() {
    super();
    this.sent = 0;
  }

  connect(other: MockConnection) {
    this.other = other;
    other.other = this;
    this.dispatchEvent(new Event('open'));
    this.other.dispatchEvent(new Event('open'));
  }

  send(msg: Uint8Array) {
    this.sent += msg.length;
    this.other.dispatchEvent(new MessageEvent('message', { data: msg }));
  }
}

test('publish', () => {
  const ab = new MockConnection();
  const ba = new MockConnection();
  const a = new Shnaker(ab, new Identity());
  const b = new Shnaker(ba, new Identity());
  ab.connect(ba);

  const data = { K: 20 };
  var gotMessage = false;
  b.subscribe([['K', '=', 20]]).addEventListener('msg', (ev: CustomEvent) => {
    const { msg, sender, hash, receiver } = ev.detail;
    expect(msg).toStrictEqual(data);
    gotMessage = true;
  });

  a.publishPublic(data);
  expect(gotMessage).toBe(true);
});
