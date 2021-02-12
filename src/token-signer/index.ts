import base64url from './base64url';
import { hashSha256 } from '../common/sha2Hash';
import * as noble from 'noble-secp256k1';
import { Buffer } from 'buffer';

export interface TokenInterface {
  header: {
    [key: string]: string | Json;
    alg?: any;
    typ?: any;
  };
  payload:
    | {
        [key: string]: Json;
        iss?: any | string;
        jti?: any | string;
        iat?: any | string | number;
        exp?: any | string | number;
      }
    | string;
  signature: string;
}

export type Json = string | number | boolean | null | { [property: string]: Json } | Json[];

// @ts-ignore
export function decodeToken(token: string | TokenInterface): TokenInterface | undefined {
  if (typeof token === 'string') {
    // decompose the token into parts
    const tokenParts = token.split('.');
    const header = JSON.parse(base64url.decode(tokenParts[0]));
    const payload = JSON.parse(base64url.decode(tokenParts[1]));
    const signature = tokenParts[2];

    // return the token object
    return {
      header: header,
      payload: payload,
      signature: signature,
    };
  } else if (typeof token === 'object') {
    if (typeof token.payload !== 'string') {
      throw new Error('Expected token payload to be a base64 or json string');
    }
    let payload = token.payload;
    if (token.payload[0] !== '{') {
      payload = base64url.decode(payload);
    }

    const allHeaders: any = [];
    (token.header as any).map((headerValue: string) => {
      const header = JSON.parse(base64url.decode(headerValue));
      allHeaders.push(header);
    });

    return {
      header: allHeaders,
      payload: JSON.parse(payload),
      signature: token.signature,
    };
  }
}

function createSigningInput(payload: Json, header: Json) {
  const tokenParts = [];

  // add in the header
  const encodedHeader = base64url.encode(JSON.stringify(header));
  tokenParts.push(encodedHeader);

  // add in the payload
  const encodedPayload = base64url.encode(JSON.stringify(payload));
  tokenParts.push(encodedPayload);

  // prepare the message
  const signingInput = tokenParts.join('.');

  // return the signing input
  return signingInput;
}

export function createUnsecuredToken(payload: Json) {
  const header = { typ: 'JWT', alg: 'none' };
  return createSigningInput(payload, header) + '.';
}

export interface SignedToken {
  header: string[];
  payload: string;
  signature: string[];
}

export class TokenSigner {
  tokenType: string;
  rawPrivateKey: string;

  constructor(signingAlgorithm: string, rawPrivateKey: string) {
    if (!(signingAlgorithm && rawPrivateKey)) {
      throw new Error('a signing algorithm and private key are required');
    }

    this.tokenType = 'JWT';

    this.rawPrivateKey = rawPrivateKey;
  }

  header(header = {}) {
    const defaultHeader = {
      typ: this.tokenType,
      alg: 'ES256K',
    };
    return Object.assign({}, defaultHeader, header);
  }

  async sign(payload: Json): Promise<string>;
  async sign(payload: Json, expanded: true, customHeader?: Json): Promise<SignedToken>;
  async sign(payload: Json, expanded: false, customHeader?: Json): Promise<string>;
  async sign(
    payload: Json,
    expanded: boolean = false,
    customHeader: Json = {}
  ): Promise<SignedToken | string> {
    // generate the token header
    const header = this.header(customHeader as any);

    // prepare the message to be signed
    const signingInput = createSigningInput(payload, header);
    const signingInputHash = await hashSha256(Buffer.from(signingInput));
    return this.createWithSignedHash(payload, expanded, header, signingInput, signingInputHash);
  }

  async createWithSignedHash(
    payload: Json,
    expanded: boolean,
    header: { typ: string; alg: string },
    signingInput: string,
    signingInputHash: Buffer
  ): Promise<SignedToken | string> {
    // sign the message and add in the signature
    const signature = Buffer.from(await noble.sign(signingInputHash, this.rawPrivateKey)).toString(
      'hex'
    );

    if (expanded) {
      const signedToken: SignedToken = {
        header: [base64url.encode(JSON.stringify(header))],
        payload: JSON.stringify(payload),
        signature: [Buffer.from(signature).toString('hex')],
      };
      return signedToken;
    } else {
      return [signingInput, signature].join('.');
    }
  }
}
