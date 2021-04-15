// @ts-ignore -- doesn't like using Buffer as type?
import { Buffer } from 'buffer';

export type NodeCryptoCreateHash = typeof import('crypto').createHash;
export type NodeCryptoCreateHmac = typeof import('crypto').createHmac;

export interface Sha2Hash {
  digest(data: Uint8Array, algorithm?: 'sha256' | 'sha512'): Promise<Buffer>;
}

export interface Hmac {
  digest(key: Uint8Array, data: Uint8Array): Promise<Buffer>;
}

export interface EncryptECIESOptions {
  publicKey: string;
  content: Buffer;
  wasString: boolean;
  cipherTextEncoding?: CipherTextEncoding;
}

export interface DecryptECIESOptions {
  privateKey: string;
  cipherObject: CipherObject;
}

/**
 * Controls how the encrypted data buffer will be encoded as a string in the JSON payload.
 * Options:
 *    `hex` -- the legacy default, file size increase 100% (2x).
 *    `base64` -- file size increased ~33%.
 * @ignore
 */
export type CipherTextEncoding = 'hex' | 'base64';

export type CipherObject = {
  iv: string;
  ephemeralPK: string;
  cipherText: string;
  /** If undefined then hex encoding is used for the `cipherText` string. */
  cipherTextEncoding?: CipherTextEncoding;
  mac: string;
  wasString: boolean;
};
