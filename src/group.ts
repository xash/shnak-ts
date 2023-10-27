import { encode, decode } from 'debif-ts';
import { Channel, Shnaker, MessageFilter, Hash } from './shnaker';
import { SymKey, Identity, PrivKey, symEncrypt, symDecrypt, deriveKey, sharedSecret, PubKey } from './crypto';

export class Group extends EventTarget {
  shnaker: Shnaker;

  groupInfoIdentity: Identity;
  groupInfoEncKey: SymKey;
  handlers: Array<any>;
  iteration?: number;

  shnakerInnerGroup: Shnaker;
  groupBroadcastIdentity: PubKey;
  groupBroadcastEnc: SymKey;
  groupRootKey: PubKey;

  infoChannel?: Channel;
  broadchastChannel?: Channel;

  canWrite: boolean;
  canRead: boolean;

  members: Array<{
    key: PubKey;
    channel: PubKey;
    channelEncKey: SymKey;
  }>;

  channelHandlers: Array<Channel>;

  constructor(shnaker: Shnaker, groupRootPubKey: PubKey) {
    super();
    this.shnaker = shnaker;
    this.groupRootKey = groupRootPubKey;
    const secret = sharedSecret(this.shnaker.id.priv, groupRootPubKey);
    const sharedChannel = deriveKey(secret, undefined, "groupChannel", 32);
    const sharedSymKey = deriveKey(secret, undefined, "groupChannelEnc", 32);
    this.groupInfoIdentity = new Identity(sharedChannel);
    this.groupInfoEncKey = new SymKey(sharedSymKey);
    this.groupBroadcastIdentity = null;
    this.iteration = null;
    this.channelHandlers = [];
    this.members = [];

    if (this.shnaker.connected) {
      this.infoChannel = this.shnaker.subscribe([["K", "=", 2]]);
      this.infoChannel.addEventListener('msg', (ev: CustomEvent) => {
        this.handleGroupInfo(ev.detail.msg, ev.detail.sender, ev.detail.hash, ev.detail.receiver);
      });
    } else
      this.shnaker.addEventListener('open', (_) => {
        this.infoChannel = this.shnaker.subscribe([["K", "=", 2]]);
        this.infoChannel.addEventListener('msg', (ev: CustomEvent) => {
          this.handleGroupInfo(ev.detail.msg, ev.detail.sender, ev.detail.hash, ev.detail.receiver);
        });
      });
  }

  handleGroupInfo(msg: any, sender: PubKey, hash: Hash, receiver?: PubKey) {
    if (!sender.equal(this.groupInfoIdentity.pub)) return;

    const encrypted = msg as {
      d: Uint8Array,
    };
    const decrypted = symDecrypt(this.groupInfoEncKey, encrypted.d);
    const m = decode(decrypted) as any;

    if (m.K == 101 &&
      (this.iteration === null || m.I > this.iteration)) {
      if (this.broadchastChannel)
        this.iteration = m.I;

      if (m.pub) {
        this.canWrite = true;
        const secret = sharedSecret(this.shnaker.id.priv, new PubKey(m.pub));
        const channelKey = deriveKey(secret, undefined, "broadcastChannel", 32);
        const channelEncKey = deriveKey(secret, undefined, "broadcastChannelEnc", 32);
        this.groupBroadcastIdentity = new PubKey(channelKey);
        this.groupBroadcastEnc = new SymKey(channelEncKey);
        this.dispatchEvent(new CustomEvent("canWrite", { detail: { members: m.members } }));
      }

      if (m.priv) {
        this.canRead = true;
        for (const member of m.members) {
          const secret = sharedSecret(new PrivKey(m.priv), new PubKey(member));
          const channelKey = deriveKey(secret, undefined, "broadcastChannel", 32);
          const channelEncKey = deriveKey(secret, undefined, "broadcastChannelEnc", 32);
          this.members.push({
            key: new PubKey(member),
            channel: new PubKey(channelKey),
            channelEncKey: new SymKey(channelEncKey),
          });
        };
        this.dispatchEvent(new CustomEvent("canRead", { detail: { members: m.members } }));
        this.broadchastChannel = this.shnaker.subscribe([["K", "=", 2]]);
        this.broadchastChannel.addEventListener('msg', (ev: CustomEvent) => {
          const { msg, sender, hash, receiver } = ev.detail;
          this.handleGroupMessage(msg, sender, hash, receiver);
        });
      }
    }
  }

  publish(obj: Object) {
    const delay = () => {
      const msg = new Uint8Array(encode(this.shnaker.msgBuf, obj));
      const payload = symEncrypt(this.groupBroadcastEnc, msg);

      this.shnaker.publishPublic({
        K: 2,
        R: this.groupBroadcastIdentity.pubBytes,
        d: payload,
      });
    };
    if (this.canWrite) delay();
    else this.addEventListener('canWrite', delay, { once: true });
  }


  subscribe(filters?: Array<MessageFilter>): Channel {
    const c = new Channel(filters);
    this.channelHandlers.push(c);
    return c;
  }

  private handleGroupMessage(msg2: any, sender: PubKey, hash: Hash, receiver?: PubKey) {
    for (const { key, channel, channelEncKey } of this.members) {
      if (!receiver || !receiver.equal(channel)) continue;
      const encrypted = msg2 as {
        d: Uint8Array,
      };
      const decrypted = symDecrypt(channelEncKey, encrypted.d);
      const msg = decode(decrypted);
      for (const channel of this.channelHandlers)
        channel.broadcast(msg, key, hash, this.groupRootKey);
    }
  }
};
