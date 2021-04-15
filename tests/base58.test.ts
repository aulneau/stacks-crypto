import { privateKeyToAddress } from '../src/addresses';
import { publicKeyToAddress } from '../src/base58';

const publicKey = '029eabdfa0902bb7fd449a9c244fea5920986c0cb3f6bddf5a04c15ca60d1df255';
const privateKey = '172e1ca4745a8021c7049f51c1cbd1edc3c4345e30822dbb2ad36a9d0d3a6912';
const base58Addr = '1HLFQqHeJSoGKpw2hjUTFhyLD6dDCTVUe1';

test(publicKeyToAddress.name, async () => {
  const addr = await publicKeyToAddress(publicKey);
  expect(addr).toEqual(base58Addr);
});

test(privateKeyToAddress.name, async () => {
  const addr = await privateKeyToAddress(privateKey);
  expect(addr).toEqual(base58Addr);
});
