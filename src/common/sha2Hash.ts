import jsSHA from 'jssha';
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
      console.log(error);
      console.log(
        `Error performing ${algorithm} digest with Node.js 'crypto.createHash', falling back to JS implementation.`
      );
      return Promise.resolve(algorithm === 'sha256' ? hashSha256Sync(data) : hashSha512Sync(data));
    }
  }
}

export class WebCryptoSha2Hash implements Sha2Hash {
  subtleCrypto: SubtleCrypto;

  constructor(subtleCrypto: SubtleCrypto) {
    this.subtleCrypto = subtleCrypto;
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
      const hash = await this.subtleCrypto.digest(algo, data);
      return Buffer.from(hash);
    } catch (error) {
      console.log(error);
      console.log(
        `Error performing ${algorithm} digest with WebCrypto, falling back to JS implementation.`
      );
      return Promise.resolve(algorithm === 'sha256' ? hashSha256Sync(data) : hashSha512Sync(data));
    }
  }
}

export async function createSha2Hash(): Promise<Sha2Hash> {
  const cryptoLib = await getCryptoLib();
  if (cryptoLib.name === 'subtleCrypto') {
    return new WebCryptoSha2Hash(cryptoLib.lib);
  } else {
    return new NodeCryptoSha2Hash(cryptoLib.lib.createHash);
  }
}

export function hashSha256Sync(data: Buffer) {
  const hash = new jsSHA('SHA-256', 'ARRAYBUFFER');
  hash.update(data);
  return Buffer.from(hash.getHash('HEX'), 'hex');
}

export function hashSha512Sync(data: Buffer) {
  const hash = new jsSHA('SHA-512', 'ARRAYBUFFER');

  hash.update(data);
  return Buffer.from(hash.getHash('HEX'), 'hex');
}
