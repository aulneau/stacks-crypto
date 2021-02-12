import { publicKeyToAddress } from '../src/base58';

const publicKey = '029eabdfa0902bb7fd449a9c244fea5920986c0cb3f6bddf5a04c15ca60d1df255';
const base58Addr = '1HLFQqHeJSoGKpw2hjUTFhyLD6dDCTVUe1';

test(publicKeyToAddress.name, async () => {
  const addr = await publicKeyToAddress(publicKey);
  expect(addr).toEqual(base58Addr);
});
