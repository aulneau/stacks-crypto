import { decodeToken, TokenVerifier as OldTokenVerifier } from 'jsontokens';
import { TokenSigner } from '../src/token-signer';
import { getPublicKey } from 'noble-secp256k1';

// from noble-secp repo readme
const privateKey = '6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e';
const publicKey = getPublicKey(privateKey);

test('can create a valid backwards compatible json token', async () => {
  const tokenSigner = new TokenSigner('ES256k', privateKey);
  const payload = {
    some: 'thing',
    with: 123,
    and: {
      nested: 'data',
    },
  };
  const token = await tokenSigner.sign(payload);
  const decoded = decodeToken(token);
  expect(decoded.payload).toEqual(payload);
  const verifier = new OldTokenVerifier('ES256k', publicKey);
  const isValid = await verifier.verifyAsync(token);
  expect(isValid).toEqual(true);
});
