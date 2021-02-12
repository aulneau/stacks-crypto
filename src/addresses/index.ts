import { Buffer } from 'buffer';
import { getPublicKey } from 'noble-secp256k1';
import { hashSha256 } from '../common/sha2Hash';
import { hashRipemd160 } from '../common/hashRipemd160';
import { base58check } from '../base58';
import { networks } from '../base58/networks';

export async function privateKeyToAddress(privateKey: string) {
  const publicKey = getPublicKey(privateKey, true); // is it compressed though?
  const sha256 = await hashSha256(Buffer.from(publicKey, 'hex'));
  const hash160 = hashRipemd160(sha256);
  return base58check(hash160, networks.bitcoin.pubKeyHash);
}

export async function publicKeyToAddress(publicKey: string) {
  const sha256 = await hashSha256(Buffer.from(publicKey, 'hex'));
  const hash160 = hashRipemd160(sha256);
  return base58check(hash160, networks.bitcoin.pubKeyHash);
}
