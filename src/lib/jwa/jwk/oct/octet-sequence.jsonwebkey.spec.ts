import { Buffer } from 'buffer';
import crypto, { KeyObject } from 'crypto';

import { InvalidJsonWebKeyError } from '../../../errors/invalid-jsonwebkey.error';
import { GenerateOctetSequenceJsonWebKeyOptions } from './generate-octet-sequence-jsonwebkey.options';
import { OctetSequenceJsonWebKey } from './octet-sequence.jsonwebkey';
import { OctetSequenceJsonWebKeyParameters } from './octet-sequence-jsonwebkey.parameters';

const invalidKs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], ''];

const invalidGenerateOptions: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  'a',
  Symbol('a'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  [],
  {},
];

const invalidLengths: any[] = [
  undefined,
  null,
  true,
  1.2,
  1n,
  'a',
  Symbol('a'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  -1,
];

describe('Octet Sequence JSON Web Key', () => {
  const parameters: OctetSequenceJsonWebKeyParameters = {
    kty: 'oct',
    k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ',
  };

  const options: GenerateOctetSequenceJsonWebKeyOptions = { length: 32 };

  describe('constructor', () => {
    it.each(invalidKs)('should throw when the provided JSON Web Key Parameter "k" is invalid.', (k) => {
      expect(() => new OctetSequenceJsonWebKey({ ...parameters, k })).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'Invalid JSON Web Key Parameter "k".',
      );
    });

    it('should return an Octet Sequence JSON Web Key.', () => {
      let jwk!: OctetSequenceJsonWebKey;

      expect(() => (jwk = new OctetSequenceJsonWebKey(parameters))).not.toThrow();

      expect(jwk.parameters).toStrictEqual(parameters);

      expect(jwk.cryptoKey).toBeInstanceOf(KeyObject);
      expect(jwk.cryptoKey.export({ format: 'jwk' })).toStrictEqual(parameters);
    });
  });

  describe('generate()', () => {
    it.each(invalidGenerateOptions)('should throw when the provided options is invalid.', async (options) => {
      await expect(OctetSequenceJsonWebKey.generate(options)).rejects.toThrowWithMessage(
        TypeError,
        'The provided options is invalid.',
      );
    });

    it.each(invalidLengths)('should throw when the provided Length is invalid.', async (length) => {
      await expect(OctetSequenceJsonWebKey.generate({ length })).rejects.toThrowWithMessage(
        TypeError,
        'The provided Length is invalid.',
      );
    });

    it('should return the generated Octet Sequence Crypto Key.', async () => {
      let cryptoKey!: KeyObject;

      await expect(async () => (cryptoKey = await OctetSequenceJsonWebKey.generate(options))).resolves.not.toThrow();

      expect(cryptoKey).toBeInstanceOf(KeyObject);
      expect(cryptoKey.export({ format: 'jwk' })).toMatchObject<OctetSequenceJsonWebKeyParameters>({
        kty: 'oct',
        k: expect.toBeString(),
      });
    });
  });

  describe('getThumbprint()', () => {
    it('should return the Thumbprint of the JSON Web Key.', () => {
      const jwk = new OctetSequenceJsonWebKey(parameters);
      const createHashSpy = jest.spyOn(crypto, 'createHash');

      expect(jwk.getThumbprint().toString('base64url')).toStrictEqual('vM7XT8f5s2ATReLbN47BWpPOuo7CTV1uv-zR8R9aOuk');
      expect(createHashSpy).toHaveBeenCalledOnce();
    });
  });

  describe('getThumbprintURI()', () => {
    it('should return the Thumbprint of the JSON Web Key.', () => {
      const jwk = new OctetSequenceJsonWebKey(parameters);

      expect(jwk.getThumbprintURI()).toStrictEqual(
        'urn:ietf:params:oauth:jwk-thumbprint:sha-256:vM7XT8f5s2ATReLbN47BWpPOuo7CTV1uv-zR8R9aOuk',
      );
    });
  });

  describe('toJSON()', () => {
    const jwk = new OctetSequenceJsonWebKey(parameters);

    it('should return the JSON Web Key Parameters of the Key when exportPrivate is undefined.', () => {
      expect(jwk.toJSON()).toStrictEqual(parameters);
    });

    it('should return the JSON Web Key Parameters of the Key when exportPrivate is false.', () => {
      expect(jwk.toJSON(false)).toStrictEqual(parameters);
    });

    it('should return the JSON Web Key Parameters of the Key when exportPrivate is true.', () => {
      expect(jwk.toJSON(true)).toStrictEqual(parameters);
    });
  });
});
