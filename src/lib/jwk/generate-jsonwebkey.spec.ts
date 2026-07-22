import { Buffer } from 'buffer';
import { KeyObject } from 'crypto';

import { KeyType } from '../jwa/jwk/key-type.type';
import { generateJsonWebKey } from './generate-jsonwebkey';
import { JsonWebKey } from './jsonwebkey';

const invalidKtys: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  Symbol('a'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  '',
  'a',
];

const keyTypeAndOptions: [KeyType, Record<string, any>][] = [
  ['EC', { curve: 'P-256' }],
  ['OKP', { curve: 'Ed25519' }],
  ['RSA', { modulus: 2048 }],
  ['oct', { length: 32 }],
];

describe('generateJsonWebKey()', () => {
  it.each(invalidKtys)('should throw when the provided JSON Web Key Key Type is invalid.', async (kty) => {
    await expect(generateJsonWebKey(kty, <any>{})).rejects.toThrowWithMessage(
      TypeError,
      'The provided JSON Web Key Key Type is invalid.',
    );
  });

  it.each(keyTypeAndOptions)('should return the generated JSON Web Key.', async (kty, options) => {
    let jwk!: JsonWebKey;

    await expect(async () => (jwk = await generateJsonWebKey(kty as any, options as any))).resolves.not.toThrow();

    expect(jwk.parameters.kty).toStrictEqual(kty);

    expect(jwk.cryptoKey).toBeInstanceOf(KeyObject);
    expect(jwk.cryptoKey.export({ format: 'jwk' })).toMatchObject(jwk.parameters);

    expect(jwk.certificateChain).toBeNull();
  });
});
