import base58 from 'micro-base58';
import { hashSha256, hashRipemd160 } from '..';
import { networks, Versions } from './networks';

// original:
// function toBase58Check(hash, version) {
//   typeforce(types.tuple(types.Hash160bit, types.UInt8), arguments);
//   const payload = Buffer.allocUnsafe(21);
//   payload.writeUInt8(version, 0);
//   hash.copy(payload, 1);
//   return bs58check.encode(payload);
// }
// @see: https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/address.js#L30

// https://github.com/paulmillr/micro-base58
export async function base58check(hash: Buffer, version: Versions) {
  const versionBuffer = Buffer.alloc(1, version);
  const data = new Uint8Array(25);
  const payload = Buffer.allocUnsafe(21);

  payload.writeUInt8(version);
  hash.copy(payload, 1);
  const sha1 = await hashSha256(payload);
  const sha2 = await hashSha256(sha1);

  const checksum = sha2.slice(0, 4);

  data.set(versionBuffer, 0);
  data.set(hash, 1);
  data.set(checksum, hash.length + 1);

  return base58(data);
}

export async function publicKeyToAddress(publicKey: string) {
  const sha256 = await hashSha256(Buffer.from(publicKey, 'hex'));
  const hash160 = hashRipemd160(sha256);

  return base58check(hash160, networks.bitcoin.pubKeyHash);
}
