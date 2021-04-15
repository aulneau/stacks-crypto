import { getSharedSecret } from 'noble-secp256k1';
import { Buffer } from 'buffer';
import { DecryptECIESOptions } from './common/types';
import {
  aes256CbcDecrypt,
  equalConstTime,
  hmacSha256,
  sharedSecretToKeys,
} from './common/ecies-helpers';

/**
 * Decrypt content encrypted using ECIES
 *  * @param options {DecryptECIESOptions}
 *  iv (initialization vector), cipherText (cipher text),
 *  mac (message authentication code), ephemeralPublicKey
 *  wasString (boolean indicating with or not to return a buffer or string on decrypt)
 * @return {Buffer} plaintext
 * @throws {Error} if unable to decrypt
 * @private
 * @ignore
 */

export async function decryptECIES(options: DecryptECIESOptions): Promise<Buffer | string> {
  const { privateKey, cipherObject } = options;

  const ephemeralPK = cipherObject.ephemeralPK;
  let sharedSecret = Buffer.from(getSharedSecret(privateKey, ephemeralPK, true) as string, 'hex');
  // Trim the compressed mode prefix byte
  sharedSecret = sharedSecret.slice(1);
  const sharedKeys = await sharedSecretToKeys(sharedSecret);
  const ivBuffer = Buffer.from(cipherObject.iv, 'hex');

  let cipherTextBuffer: Buffer;

  if (!cipherObject.cipherTextEncoding || cipherObject.cipherTextEncoding === 'hex') {
    cipherTextBuffer = Buffer.from(cipherObject.cipherText, 'hex');
  } else if (cipherObject.cipherTextEncoding === 'base64') {
    cipherTextBuffer = Buffer.from(cipherObject.cipherText, 'base64');
  } else {
    throw new Error(`Unexpected cipherTextEncoding "${cipherObject.cipherText}"`);
  }

  const macData = Buffer.concat([ivBuffer, Buffer.from(ephemeralPK, 'hex'), cipherTextBuffer]);
  const actualMac = await hmacSha256(sharedKeys.hmacKey, macData);
  const expectedMac = Buffer.from(cipherObject.mac, 'hex');

  if (!equalConstTime(expectedMac, actualMac)) {
    throw new Error('Decryption failed: failure in MAC check');
  }
  const plainText = await aes256CbcDecrypt(ivBuffer, sharedKeys.encryptionKey, cipherTextBuffer);

  if (cipherObject.wasString) {
    return plainText.toString();
  } else {
    return plainText;
  }
}
