import { getCryptoLib } from './crypto-utils';
import { Buffer } from 'buffer';
import type { Hmac, NodeCryptoCreateHmac } from './types';

export class NodeCryptoHmacSha256 implements Hmac {
  createHmac: NodeCryptoCreateHmac;

  constructor(createHmac: NodeCryptoCreateHmac) {
    this.createHmac = createHmac;
  }

  async digest(key: Uint8Array, data: Uint8Array): Promise<Buffer> {
    const result = this.createHmac('sha256', key).update(data).digest();
    return Promise.resolve(result);
  }
}

export class WebCryptoHmacSha256 implements Hmac {
  webCrypto: Crypto;

  constructor(webCrypto: Crypto) {
    this.webCrypto = webCrypto;
  }

  async digest(key: Uint8Array, data: Uint8Array): Promise<Buffer> {
    const cryptoKey = await this.webCrypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: 'SHA-256' },
      true,
      ['sign']
    );
    const sig = await this.webCrypto.subtle.sign(
      // The `hash` is only specified for non-compliant browsers like Edge.
      { name: 'HMAC', hash: 'SHA-256' },
      cryptoKey,
      data
    );
    return Buffer.from(sig);
  }
}

export async function createHmacSha256(): Promise<Hmac> {
  const cryptoLib = await getCryptoLib();
  if (cryptoLib.name === 'webCrypto') {
    return new WebCryptoHmacSha256(cryptoLib.lib);
  } else {
    return new NodeCryptoHmacSha256(cryptoLib.lib.createHmac);
  }
}
