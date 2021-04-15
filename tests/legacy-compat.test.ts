import { encryptECIES, decryptECIES } from '../src';
import { makeECPrivateKey, getPublicKeyFromPrivate, decryptContent as legacyDecrypt, encryptContent as legacyEncrypt } from '@stacks/encryption';

test('New encrypt can be decrypted by legacy', async () => {
  const privateKey = makeECPrivateKey();
  const publicKey = getPublicKeyFromPrivate(privateKey);

  const original = 'hello world';

  const cipherObject = await encryptECIES({
    publicKey,
    content: Buffer.from(original),
    wasString: true,
  });

  const decrypted = await legacyDecrypt(JSON.stringify(cipherObject), {
    privateKey,
  });

  expect(original).toEqual(decrypted);
});

test('Legacy encrypt can be decrypted by new', async () => {
  const privateKey = makeECPrivateKey();
  const publicKey = getPublicKeyFromPrivate(privateKey);

  const original = 'hello world';

  const cipherObject = await legacyEncrypt(Buffer.from(original), {
    publicKey,
    wasString: true,
  });

  const decrypted = await decryptECIES({
    privateKey, 
    cipherObject: JSON.parse(cipherObject)
  });

  expect(original).toEqual(decrypted);
});