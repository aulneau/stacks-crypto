import { encryptECIES } from '../src';
import { makeECPrivateKey, getPublicKeyFromPrivate, decryptContent } from '@stacks/encryption';

test('New encrypt can be decrypted by legacy', async () => {
  const privateKey = makeECPrivateKey();
  const publicKey = getPublicKeyFromPrivate(privateKey);

  const original = 'hello world';

  const cipherObject = await encryptECIES({
    publicKey,
    content: Buffer.from(original),
    wasString: true,
  });

  const decrypted = await decryptContent(JSON.stringify(cipherObject), {
    privateKey,
  });

  expect(original).toEqual(decrypted);
});
