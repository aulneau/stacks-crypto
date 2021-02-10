import { createCipher } from './aes-cypher';
import { createHmacSha256 } from './hmacSha256';
import { hashSha512Sync } from './sha2Hash';

// @ts-ignore -- doesn't like using Buffer as type?
import { Buffer } from 'buffer';

export async function aes256CbcEncrypt(
  iv: Buffer,
  key: Buffer,
  plaintext: Buffer
): Promise<Buffer> {
  const cipher = await createCipher();
  const result = await cipher.encrypt('aes-256-cbc', key, iv, plaintext);
  return result;
}

export async function hmacSha256(key: Buffer, content: Buffer) {
  const hmacSha256 = await createHmacSha256();
  return hmacSha256.digest(key, content);
}

export function sharedSecretToKeys(
  sharedSecret: Buffer
): { encryptionKey: Buffer; hmacKey: Buffer } {
  // generate mac and encryption key from shared secret
  const hashedSecret = hashSha512Sync(sharedSecret);
  return {
    encryptionKey: hashedSecret.slice(0, 32),
    hmacKey: hashedSecret.slice(32),
  };
}

export function equalConstTime(b1: Buffer, b2: Buffer) {
  if (b1.length !== b2.length) {
    return false;
  }
  let res = 0;
  for (let i = 0; i < b1.length; i++) {
    res |= b1[i] ^ b2[i]; // jshint ignore:line
  }
  return res === 0;
}

export async function aes256CbcDecrypt(
  iv: Buffer,
  key: Buffer,
  ciphertext: Buffer
): Promise<Buffer> {
  const cipher = await createCipher();
  const result = await cipher.decrypt('aes-256-cbc', key, iv, ciphertext);
  return result;
}
