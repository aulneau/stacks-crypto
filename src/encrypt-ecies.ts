import { getPublicKey, getSharedSecret, utils } from 'noble-secp256k1';
import randomBytes from 'randombytes';
import { Buffer } from 'buffer';
import { sharedSecretToKeys, aes256CbcEncrypt, hmacSha256 } from './common/ecies-helpers';
import { CipherObject, EncryptECIESOptions } from './common/types';

export async function encryptECIES(options: EncryptECIESOptions): Promise<CipherObject> {
  const { publicKey, content, cipherTextEncoding, wasString } = options;
  const ephemeralPrivateKey = Buffer.from(utils.randomPrivateKey()).toString('hex');
  const ephemeralPublicKey = Buffer.from(getPublicKey(ephemeralPrivateKey), 'hex');
  const sharedKey = getSharedSecret(ephemeralPrivateKey, publicKey);
  const sharedKeys = sharedSecretToKeys(Buffer.from(sharedKey));
  const initializationVector = randomBytes(16);

  const cipherText = await aes256CbcEncrypt(
    initializationVector,
    sharedKeys.encryptionKey,
    content
  );

  const macData = Buffer.concat([initializationVector, ephemeralPublicKey, cipherText]);
  const mac = await hmacSha256(sharedKeys.hmacKey, macData);

  let cipherTextString: string;

  if (!cipherTextEncoding || cipherTextEncoding === 'hex') {
    cipherTextString = cipherText.toString('hex');
  } else if (cipherTextEncoding === 'base64') {
    cipherTextString = cipherText.toString('base64');
  } else {
    throw new Error(`Unexpected cipherTextEncoding "${cipherTextEncoding}"`);
  }

  const result: CipherObject = {
    iv: initializationVector.toString('hex'),
    ephemeralPK: ephemeralPublicKey.toString('hex'),
    cipherText: cipherTextString,
    mac: mac.toString('hex'),
    wasString,
  };
  if (cipherTextEncoding && cipherTextEncoding !== 'hex') {
    result.cipherTextEncoding = cipherTextEncoding;
  }
  return result;
}
