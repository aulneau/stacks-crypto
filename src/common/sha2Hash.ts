import { Buffer } from 'buffer';
import { getCryptoLib } from './crypto-utils';

import type { NodeCryptoCreateHash, Sha2Hash } from './types';

export class NodeCryptoSha2Hash {
  createHash: NodeCryptoCreateHash;

  constructor(createHash: NodeCryptoCreateHash) {
    this.createHash = createHash;
  }

  async digest(data: Buffer, algorithm = 'sha256'): Promise<Buffer> {
    try {
      const result = this.createHash(algorithm).update(data).digest();
      return Promise.resolve(result);
    } catch (error) {
      console.error(error);
      console.error(`Error performing ${algorithm} digest with Node.js 'crypto.createHash'`);
      throw error;
    }
  }
}

export class WebCryptoSha2Hash implements Sha2Hash {
  webCrypto: Crypto;

  constructor(webCrypto: Crypto) {
    this.webCrypto = webCrypto;
  }

  async digest(data: Buffer, algorithm = 'sha256'): Promise<Buffer> {
    let algo: string;
    if (algorithm === 'sha256') {
      algo = 'SHA-256';
    } else if (algorithm === 'sha512') {
      algo = 'SHA-512';
    } else {
      throw new Error(`Unsupported hash algorithm ${algorithm}`);
    }
    try {
      const hash = await this.webCrypto.subtle.digest(algo, data);
      return Buffer.from(hash);
    } catch (error) {
      console.error(error);
      console.error(`Error performing ${algorithm} digest with WebCrypto.`);
      throw error;
    }
  }
}

export async function createSha2Hash(): Promise<Sha2Hash> {
  const cryptoLib = await getCryptoLib();
  if (cryptoLib.name === 'webCrypto') {
    return new WebCryptoSha2Hash(cryptoLib.lib);
  } else {
    return new NodeCryptoSha2Hash(cryptoLib.lib.createHash);
  }
}

export async function hashSha256(data: Buffer): Promise<Buffer> {
  const hash = await createSha2Hash();
  return await hash.digest(data, 'sha256');
}

export async function hashSha512(data: Buffer): Promise<Buffer> {
  const hash = await createSha2Hash();
  return await hash.digest(data, 'sha512');
}
