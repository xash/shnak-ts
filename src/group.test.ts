import { expect, test } from 'vitest'

import { Group } from './group';
import { Shnaker } from './shnaker';
import { Identity } from './crypto';

class MockBroadcast {
  channels: Array<any>;
  sent: number;
  cnt: number;

  constructor(amount: number) {
    this.sent = 0;
    this.cnt = 0;
    this.channels = [];
    for (let i = 0; i < amount; i++)
      this.channels.push(
        new EventTarget());
    for (let i = 0; i < amount; i++) {
      this.channels[i].send = (msg) => {
        this.sent += msg.length;
        this.cnt++;
        for (let j = 0; j < amount; j++) {
          // if (i == j) continue;
          this.channels[j].dispatchEvent(new MessageEvent('message', { data: msg }))
        }
      };
    }
  }

  connect() {
    for (const channel of this.channels) {
      channel.dispatchEvent(new Event('open'));
    }
  }
}

test('group', () => {
  const bc = new MockBroadcast(4);
  const group = new Shnaker(bc.channels[0], new Identity());
  const a = new Shnaker(bc.channels[1], new Identity());
  const b = new Shnaker(bc.channels[2], new Identity());
  const c = new Shnaker(bc.channels[3], new Identity());
  bc.connect();

  const ag = new Group(a, group.id.pub);
  const bg = new Group(b, group.id.pub);
  const cg = new Group(c, group.id.pub);

  let data = { K: 20 };
  let gotMessage = false;

  ag.subscribe([['K', '=', 20]]).addEventListener('msg', (ev: CustomEvent) => {
    const { msg, sender, hash, receiver } = ev.detail;
    expect(msg).toStrictEqual(data);
    gotMessage = true;
  });
  bg.publish(data);

  group.initGroup([
    { key: a.id.pub, write: true, read: true },
    { key: b.id.pub, write: true, read: true },
    { key: c.id.pub, write: true, read: true },
  ], 1);

  expect(gotMessage).toBe(true);
});
