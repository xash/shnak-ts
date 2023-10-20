import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';

type PublicKey = Uint8Array;
type Signature = Uint8Array;
type Hash = Uint8Array;

export class Signer {
  priv: Uint8Array;
  pub: PublicKey;

  constructor(key: null | Uint8Array) {
    this.priv = key === null ? ed25519.utils.randomPrivateKey() : key;
    this.pub = ed25519.getPublicKey(this.priv);
  }

  async sign(hash: Hash) {
    const buf = new Uint8Array(33);
    buf[0] = 0;
    buf.set(hash, 1);
    ed25519.sign(buf, this.priv);
  }
}

export function hash(pub: PublicKey, msg: Uint8Array) {
  return sha256.create()
    .update(pub)
    .update(msg)
    .digest();
}

export function verify(sig: Signature, hash: Hash, pub: Uint8Array) {
  const buf = new Uint8Array(33);
  buf[0] = 0;
  buf.set(hash, 1);
  return ed25519.verify(sig, hash, pub, { zip215: true });
}

