import { getCryptoLib } from './crypto-utils';
import { Buffer } from 'buffer';

type NodeCryptoCreateCipher = typeof import('crypto').createCipheriv;
type NodeCryptoCreateDecipher = typeof import('crypto').createDecipheriv;

export type CipherAlgorithm = 'aes-256-cbc' | 'aes-128-cbc';

export interface AesCipher {
  encrypt(algorithm: CipherAlgorithm, key: Buffer, iv: Buffer, data: Buffer): Promise<Buffer>;

  decrypt(algorithm: CipherAlgorithm, key: Buffer, iv: Buffer, data: Buffer): Promise<Buffer>;
}

export class NodeCryptoAesCipher implements AesCipher {
  createCipher: NodeCryptoCreateCipher;
  createDecipher: NodeCryptoCreateDecipher;

  constructor(createCipher: NodeCryptoCreateCipher, createDecipher: NodeCryptoCreateDecipher) {
    this.createCipher = createCipher;
    this.createDecipher = createDecipher;
  }

  async encrypt(
    algorithm: CipherAlgorithm,
    key: Buffer,
    iv: Buffer,
    data: Buffer
  ): Promise<Buffer> {
    if (algorithm !== 'aes-128-cbc' && algorithm !== 'aes-256-cbc') {
      throw new Error(`Unsupported cipher algorithm "${algorithm}"`);
    }
    const cipher = this.createCipher(algorithm, key, iv);
    const result = Buffer.concat([cipher.update(data), cipher.final()]);
    return Promise.resolve(result);
  }

  async decrypt(
    algorithm: CipherAlgorithm,
    key: Buffer,
    iv: Buffer,
    data: Buffer
  ): Promise<Buffer> {
    if (algorithm !== 'aes-128-cbc' && algorithm !== 'aes-256-cbc') {
      throw new Error(`Unsupported cipher algorithm "${algorithm}"`);
    }
    const cipher = this.createDecipher(algorithm, key, iv);
    const result = Buffer.concat([cipher.update(data), cipher.final()]);
    return Promise.resolve(result);
  }
}

export class WebCryptoAesCipher implements AesCipher {
  webCrypto: Crypto;

  constructor(webCrypto: Crypto) {
    this.webCrypto = webCrypto;
  }

  async encrypt(
    algorithm: CipherAlgorithm,
    key: Buffer,
    iv: Buffer,
    data: Buffer
  ): Promise<Buffer> {
    let algo: string;
    let length: number;
    if (algorithm === 'aes-128-cbc') {
      algo = 'AES-CBC';
      length = 128;
    } else if (algorithm === 'aes-256-cbc') {
      algo = 'AES-CBC';
      length = 256;
    } else {
      throw new Error(`Unsupported cipher algorithm "${algorithm}"`);
    }
    const cryptoKey = await this.webCrypto.subtle.importKey(
      'raw',
      key,
      { name: algo, length },
      false,
      ['encrypt']
    );
    const result = await this.webCrypto.subtle.encrypt({ name: algo, iv }, cryptoKey, data);
    return Buffer.from(result);
  }

  async decrypt(
    algorithm: CipherAlgorithm,
    key: Buffer,
    iv: Buffer,
    data: Buffer
  ): Promise<Buffer> {
    let algo: string;
    let length: number;
    if (algorithm === 'aes-128-cbc') {
      algo = 'AES-CBC';
      length = 128;
    } else if (algorithm === 'aes-256-cbc') {
      algo = 'AES-CBC';
      length = 256;
    } else {
      throw new Error(`Unsupported cipher algorithm "${algorithm}"`);
    }
    const cryptoKey = await this.webCrypto.subtle.importKey(
      'raw',
      key,
      { name: algo, length },
      false,
      ['decrypt']
    );
    const result = await this.webCrypto.subtle.decrypt({ name: algo, iv }, cryptoKey, data);
    return Buffer.from(result);
  }
}

export async function createCipher(): Promise<AesCipher> {
  const cryptoLib = await getCryptoLib();
  if (cryptoLib.name === 'webCrypto') {
    return new WebCryptoAesCipher(cryptoLib.lib);
  } else {
    return new NodeCryptoAesCipher(cryptoLib.lib.createCipheriv, cryptoLib.lib.createDecipheriv);
  }
}
