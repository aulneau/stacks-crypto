import base58 from 'micro-base58';

// original:
// function toBase58Check(hash, version) {
//   typeforce(types.tuple(types.Hash160bit, types.UInt8), arguments);
//   const payload = Buffer.allocUnsafe(21);
//   payload.writeUInt8(version, 0);
//   hash.copy(payload, 1);
//   return bs58check.encode(payload);
// }
// @see: https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/address.js#L30

// https://github.com/paulmillr/micro-base58
export async function base58check(hash: any, version: any) {
  const checksum = hash.slice(0, 4);
  const data = new Uint8Array(hash.length + 4);

  data.set(hash, 0);
  data.set(checksum, hash.length);

  return base58(data);
}
