import { Buffer } from 'buffer';
import crypto, { KeyObject } from 'crypto';

import { InvalidJsonWebKeyError } from '../../../errors/invalid-jsonwebkey.error';
import { GenerateOctetKeyPairJsonWebKeyOptions } from './generate-octet-key-pair-jsonwebkey.options';
import { OctetKeyPairJsonWebKey } from './octet-key-pair.jsonwebkey';
import { OctetKeyPairJsonWebKeyParameters } from './octet-key-pair-jsonwebkey.parameters';

const invalidCurves: any[] = [
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

const invalidXs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], ''];
const invalidDs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], ''];

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

describe('Octet Key Pair JSON Web Key', () => {
  const publicParameters: OctetKeyPairJsonWebKeyParameters = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: 'aNoALKSUE1UsotuZvHUj1HEGqhpzLtsSTLmkBITDMAk',
  };

  const privateParameters: OctetKeyPairJsonWebKeyParameters = {
    ...publicParameters,
    d: 'tccuS3jrlRwPaNsn2YxpUuMCqvnlsIgy_T0S7qVmo-A',
  };

  const options: GenerateOctetKeyPairJsonWebKeyOptions = { curve: 'Ed25519' };

  beforeEach(() => {
    jest.restoreAllMocks();
  });

  describe('constructor', () => {
    it.each(invalidCurves)('should throw when the provided JSON Web Key Parameter "crv" is invalid.', (crv) => {
      expect(() => new OctetKeyPairJsonWebKey({ ...publicParameters, crv })).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'Invalid JSON Web Key Parameter "crv".',
      );
    });

    it.each(invalidXs)('should throw when the provided JSON Web Key Parameter "x" is invalid.', (x) => {
      expect(() => new OctetKeyPairJsonWebKey({ ...publicParameters, x })).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'Invalid JSON Web Key Parameter "x".',
      );
    });

    it.each(invalidDs)('should throw when the provided JSON Web Key Parameter "d" is invalid.', (d) => {
      expect(() => new OctetKeyPairJsonWebKey({ ...publicParameters, d })).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'Invalid JSON Web Key Parameter "d".',
      );
    });

    it('should return a Public Octet Key Pair JSON Web Key.', () => {
      let jsonWebKey!: OctetKeyPairJsonWebKey;

      expect(() => (jsonWebKey = new OctetKeyPairJsonWebKey(publicParameters))).not.toThrow();

      expect(jsonWebKey.parameters).toStrictEqual(publicParameters);

      expect(jsonWebKey.cryptoKey).toBeInstanceOf(KeyObject);
      expect(jsonWebKey.cryptoKey.export({ format: 'jwk' })).toStrictEqual(publicParameters);
    });

    it('should return a Private Octet Key Pair JSON Web Key.', () => {
      let jsonWebKey!: OctetKeyPairJsonWebKey;

      expect(() => (jsonWebKey = new OctetKeyPairJsonWebKey(privateParameters))).not.toThrow();

      expect(jsonWebKey.parameters).toStrictEqual(privateParameters);

      expect(jsonWebKey.cryptoKey).toBeInstanceOf(KeyObject);
      expect(jsonWebKey.cryptoKey.export({ format: 'jwk' })).toStrictEqual(privateParameters);
    });
  });

  describe('generate()', () => {
    it.each(invalidGenerateOptions)('should throw when the provided options is invalid.', async (options) => {
      await expect(OctetKeyPairJsonWebKey.generate(options)).rejects.toThrowWithMessage(
        TypeError,
        'The provided options is invalid.',
      );
    });

    it.each(invalidCurves)('should throw when the provided Curve is invalid.', async (curve) => {
      await expect(OctetKeyPairJsonWebKey.generate({ curve })).rejects.toThrowWithMessage(
        TypeError,
        'The provided Curve is invalid.',
      );
    });

    it('should return the generated Octet Key Pair Crypto Key.', async () => {
      let cryptoKey!: KeyObject;

      await expect(async () => (cryptoKey = await OctetKeyPairJsonWebKey.generate(options))).resolves.not.toThrow();

      expect(cryptoKey).toBeInstanceOf(KeyObject);
      expect(cryptoKey.export({ format: 'jwk' })).toMatchObject<OctetKeyPairJsonWebKeyParameters>({
        kty: 'OKP',
        crv: 'Ed25519',
        x: expect.toBeString(),
        d: expect.toBeString(),
      });
    });
  });

  describe('getThumbprint()', () => {
    it('should return the Thumbprint of the Public JSON Web Key.', () => {
      const jsonWebKey = new OctetKeyPairJsonWebKey(publicParameters);
      const createHashSpy = jest.spyOn(crypto, 'createHash');

      expect(jsonWebKey.getThumbprint().toString('base64url')).toStrictEqual(
        'FMCIgXO9kw0AgfBekvZMOJNulldoS-m3iRokV_t4r8g',
      );
      expect(createHashSpy).toHaveBeenCalledOnce();
    });

    it('should return the Thumbprint of the Private JSON Web Key.', () => {
      const jsonWebKey = new OctetKeyPairJsonWebKey(privateParameters);
      const createHashSpy = jest.spyOn(crypto, 'createHash');

      expect(jsonWebKey.getThumbprint().toString('base64url')).toStrictEqual(
        'FMCIgXO9kw0AgfBekvZMOJNulldoS-m3iRokV_t4r8g',
      );
      expect(createHashSpy).toHaveBeenCalledOnce();
    });
  });

  describe('getThumbprintURI()', () => {
    it('should return the Thumbprint of the Public JSON Web Key.', () => {
      const jsonWebKey = new OctetKeyPairJsonWebKey(publicParameters);

      expect(jsonWebKey.getThumbprintURI()).toStrictEqual(
        'urn:ietf:params:oauth:jwk-thumbprint:sha-256:FMCIgXO9kw0AgfBekvZMOJNulldoS-m3iRokV_t4r8g',
      );
    });

    it('should return the Thumbprint of the Private JSON Web Key.', () => {
      const jsonWebKey = new OctetKeyPairJsonWebKey(privateParameters);

      expect(jsonWebKey.getThumbprintURI()).toStrictEqual(
        'urn:ietf:params:oauth:jwk-thumbprint:sha-256:FMCIgXO9kw0AgfBekvZMOJNulldoS-m3iRokV_t4r8g',
      );
    });
  });

  describe('toJSON()', () => {
    const publicJsonWebKey = new OctetKeyPairJsonWebKey(publicParameters);
    const privateJsonWebKey = new OctetKeyPairJsonWebKey(privateParameters);

    it('should return the Public JSON Web Key Parameters of the Public Key when exportPrivate is undefined.', () => {
      expect(publicJsonWebKey.toJSON()).toStrictEqual(publicParameters);
    });

    it('should return the Public JSON Web Key Parameters of the Public Key when exportPrivate is false.', () => {
      expect(publicJsonWebKey.toJSON(false)).toStrictEqual(publicParameters);
    });

    it('should return the Public JSON Web Key Parameters of the Public Key when exportPrivate is true.', () => {
      expect(publicJsonWebKey.toJSON(true)).toStrictEqual(publicParameters);
    });

    it('should return the Public JSON Web Key Parameters of the Private Key when exportPrivate is undefined.', () => {
      expect(privateJsonWebKey.toJSON()).toStrictEqual(publicParameters);
    });

    it('should return the Public JSON Web Key Parameters of the Private Key when exportPrivate is false.', () => {
      expect(privateJsonWebKey.toJSON(false)).toStrictEqual(publicParameters);
    });

    it('should return the Private JSON Web Key Parameters of the Private Key when exportPrivate is true.', () => {
      expect(privateJsonWebKey.toJSON(true)).toStrictEqual(privateParameters);
    });
  });
});
