import { Buffer } from 'buffer';
import { getCryptoLib } from './crypto-utils';

export async function getRandomBytes(size: number): Promise<Buffer> {
  const cryptoLib = await getCryptoLib();
  if (cryptoLib.name === 'webCrypto') {
    return cryptoLib.lib.getRandomValues(Buffer.alloc(size));
  } else {
    return cryptoLib.lib.randomBytes(size);
  }
}
