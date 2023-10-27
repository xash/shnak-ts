import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';
import { x25519 } from '@noble/curves/ed25519';
import { xchacha20 } from '@noble/ciphers/chacha';
import { hkdf } from '@noble/hashes/hkdf';
import { equalBuffer } from './helper';

export class PubKey {
  pubBytes: Uint8Array;
  static fromString(str: string): PubKey {
    return new PubKey(Uint8Array.from(atob(str), (m) => m.codePointAt(0)));
  }

  constructor(bytes: Uint8Array) {
    if (bytes.byteLength != 32) throw new Error('not correct size');
    this.pubBytes = bytes;
  }

  equal(other: PubKey): boolean {
    return equalBuffer(this.pubBytes, other.pubBytes);
  }

  toString(): string {
    return btoa(String.fromCodePoint(...this.pubBytes));
  }
};

export class PrivKey {
  privBytes: Uint8Array;
  constructor(bytes: Uint8Array) {
    if (bytes.byteLength != 32) throw new Error('not correct size');
    this.privBytes = bytes;
  }

  toString() { throw new Error("trying to stringify private key"); }
};

export class SymKey {
  symBytes: Uint8Array;
  constructor(bytes: Uint8Array) {
    if (bytes.byteLength != 32) throw new Error('not correct size');
    this.symBytes = bytes;
  }
};

type PublicKey = Uint8Array;
type Signature = Uint8Array;
type Hash = Uint8Array;

export function randomBytes(len: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(len));
}

export function sharedSecret(priv: PrivKey, pub: PubKey): Uint8Array {
  const xPub = edwardsToMontgomeryPub(pub.pubBytes);
  const xPriv = edwardsToMontgomeryPriv(priv.privBytes);
  return x25519.getSharedSecret(xPriv, xPub);
}

export function deriveKey(privInput: Uint8Array, salt: Uint8Array, info: string, outSize: number): Uint8Array {
  return hkdf(sha256, privInput, salt, info, outSize);
}

export function symEncrypt(key: SymKey, msg: Uint8Array): Uint8Array {
  const nonce = randomBytes(24);
  const payload = xchacha20(key.symBytes, nonce, msg);
  const data = new Uint8Array(24 + payload.length);
  data.set(nonce);
  data.set(payload, 24);
  return data;
}

export function symDecrypt(key: SymKey, msg: Uint8Array): Uint8Array {
  const nonce = msg.slice(0, 24);
  const payload = msg.slice(24);
  return xchacha20(key.symBytes, nonce, payload);
}


export class Identity {
  priv: PrivKey;
  pub: PubKey;

  constructor(key?: Uint8Array) {
    this.priv = new PrivKey(key === undefined ? ed25519.utils.randomPrivateKey() : key);
    this.pub = new PubKey(ed25519.getPublicKey(this.priv.privBytes));
  }

  sign(hash: Hash) {
    const buf = new Uint8Array(33);
    buf[0] = 0;
    buf.set(hash, 1);
    return ed25519.sign(buf, this.priv.privBytes);
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

