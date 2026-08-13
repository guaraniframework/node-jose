import { Buffer } from 'buffer';
import { KeyObject } from 'crypto';

import { KeyType } from '../jwa/jwk/key-type.type';
import { generate } from './generate';
import { JsonWebKey } from './jsonwebkey';

const invalidKeyTypes: any[] = [
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

describe('generate()', () => {
  it.each(invalidKeyTypes)('should throw when the provided JSON Web Key Key Type is invalid.', async (kty) => {
    await expect(generate(kty, <any>{})).rejects.toThrowWithMessage(
      TypeError,
      'The provided JSON Web Key Key Type is invalid.',
    );
  });

  it.each(keyTypeAndOptions)('should return the generated JSON Web Key.', async (kty, options) => {
    let jsonWebKey!: JsonWebKey;

    await expect(async () => (jsonWebKey = await generate(kty as any, options as any))).resolves.not.toThrow();

    expect(jsonWebKey.parameters.kty).toStrictEqual(kty);

    expect(jsonWebKey.cryptoKey).toBeInstanceOf(KeyObject);
    expect(jsonWebKey.cryptoKey.export({ format: 'jwk' })).toMatchObject(jsonWebKey.parameters);

    expect(jsonWebKey.certificateChain).toBeNull();
  });
});
