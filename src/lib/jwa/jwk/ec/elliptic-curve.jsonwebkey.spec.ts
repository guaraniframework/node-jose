import { Buffer } from 'buffer';
import crypto, { KeyObject } from 'crypto';

import { InvalidJsonWebKeyError } from '../../../errors/invalid-jsonwebkey.error';
import { EllipticCurveJsonWebKey } from './elliptic-curve.jsonwebkey';
import { EllipticCurveJsonWebKeyParameters } from './elliptic-curve-jsonwebkey.parameters';
import { GenerateEllipticCurveJsonWebKeyOptions } from './generate-elliptic-curve-jsonwebkey.options';

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
const invalidYs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], ''];
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

describe('Elliptic Curve JSON Web Key', () => {
  const publicParameters: EllipticCurveJsonWebKeyParameters = {
    kty: 'EC',
    crv: 'P-256',
    x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
    y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
  };

  const privateParameters: EllipticCurveJsonWebKeyParameters = {
    ...publicParameters,
    d: 'bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo',
  };

  const options: GenerateEllipticCurveJsonWebKeyOptions = { curve: 'secp256k1' };

  beforeEach(() => {
    jest.restoreAllMocks();
  });

  describe('constructor', () => {
    it.each(invalidCurves)('should throw when the provided JSON Web Key Parameter "crv" is invalid.', (crv) => {
      expect(() => new EllipticCurveJsonWebKey({ ...publicParameters, crv })).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'Invalid JSON Web Key Parameter "crv".',
      );
    });

    it.each(invalidXs)('should throw when the provided JSON Web Key Parameter "x" is invalid.', (x) => {
      expect(() => new EllipticCurveJsonWebKey({ ...publicParameters, x })).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'Invalid JSON Web Key Parameter "x".',
      );
    });

    it.each(invalidYs)('should throw when the provided JSON Web Key Parameter "y" is invalid.', (y) => {
      expect(() => new EllipticCurveJsonWebKey({ ...publicParameters, y })).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'Invalid JSON Web Key Parameter "y".',
      );
    });

    it.each(invalidDs)('should throw when the provided JSON Web Key Parameter "d" is invalid.', (d) => {
      expect(() => new EllipticCurveJsonWebKey({ ...publicParameters, d })).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'Invalid JSON Web Key Parameter "d".',
      );
    });

    it('should return a Public Elliptic Curve JSON Web Key.', () => {
      let jsonWebKey!: EllipticCurveJsonWebKey;

      expect(() => (jsonWebKey = new EllipticCurveJsonWebKey(publicParameters))).not.toThrow();

      expect(jsonWebKey.parameters).toStrictEqual(publicParameters);

      expect(jsonWebKey.cryptoKey).toBeInstanceOf(KeyObject);
      expect(jsonWebKey.cryptoKey.export({ format: 'jwk' })).toStrictEqual(publicParameters);
    });

    it('should return a Private Elliptic Curve JSON Web Key.', () => {
      let jsonWebKey!: EllipticCurveJsonWebKey;

      expect(() => (jsonWebKey = new EllipticCurveJsonWebKey(privateParameters))).not.toThrow();

      expect(jsonWebKey.parameters).toStrictEqual(privateParameters);

      expect(jsonWebKey.cryptoKey).toBeInstanceOf(KeyObject);
      expect(jsonWebKey.cryptoKey.export({ format: 'jwk' })).toStrictEqual(privateParameters);
    });
  });

  describe('generate()', () => {
    it.each(invalidGenerateOptions)('should throw when the provided options is invalid.', async (options) => {
      await expect(EllipticCurveJsonWebKey.generate(options)).rejects.toThrowWithMessage(
        TypeError,
        'The provided options is invalid.',
      );
    });

    it.each(invalidCurves)('should throw when the provided Elliptic Curve is invalid.', async (curve) => {
      await expect(EllipticCurveJsonWebKey.generate({ curve })).rejects.toThrowWithMessage(
        TypeError,
        'The provided Elliptic Curve is invalid.',
      );
    });

    it('should return the generated Elliptic Curve Crypto Key.', async () => {
      let cryptoKey!: KeyObject;

      await expect(async () => (cryptoKey = await EllipticCurveJsonWebKey.generate(options))).resolves.not.toThrow();

      expect(cryptoKey).toBeInstanceOf(KeyObject);
      expect(cryptoKey.export({ format: 'jwk' })).toMatchObject<EllipticCurveJsonWebKeyParameters>({
        kty: 'EC',
        crv: 'secp256k1',
        x: expect.toBeString(),
        y: expect.toBeString(),
        d: expect.toBeString(),
      });
    });
  });

  describe('getThumbprint()', () => {
    it('should return the Thumbprint of the Public JSON Web Key.', () => {
      const jsonWebKey = new EllipticCurveJsonWebKey(publicParameters);
      const createHashSpy = jest.spyOn(crypto, 'createHash');

      expect(jsonWebKey.getThumbprint().toString('base64url')).toStrictEqual(
        'LHM5p37TAesdI-tFqs7LOmDufKjrU0nq1jFRwI_7mvI',
      );
      expect(createHashSpy).toHaveBeenCalledOnce();
    });

    it('should return the Thumbprint of the Private JSON Web Key.', () => {
      const jsonWebKey = new EllipticCurveJsonWebKey(privateParameters);
      const createHashSpy = jest.spyOn(crypto, 'createHash');

      expect(jsonWebKey.getThumbprint().toString('base64url')).toStrictEqual(
        'LHM5p37TAesdI-tFqs7LOmDufKjrU0nq1jFRwI_7mvI',
      );
      expect(createHashSpy).toHaveBeenCalledOnce();
    });
  });

  describe('getThumbprintURI()', () => {
    it('should return the Thumbprint of the Public JSON Web Key.', () => {
      const jsonWebKey = new EllipticCurveJsonWebKey(publicParameters);

      expect(jsonWebKey.getThumbprintURI()).toStrictEqual(
        'urn:ietf:params:oauth:jwk-thumbprint:sha-256:LHM5p37TAesdI-tFqs7LOmDufKjrU0nq1jFRwI_7mvI',
      );
    });

    it('should return the Thumbprint of the Private JSON Web Key.', () => {
      const jsonWebKey = new EllipticCurveJsonWebKey(privateParameters);

      expect(jsonWebKey.getThumbprintURI()).toStrictEqual(
        'urn:ietf:params:oauth:jwk-thumbprint:sha-256:LHM5p37TAesdI-tFqs7LOmDufKjrU0nq1jFRwI_7mvI',
      );
    });
  });

  describe('toJSON()', () => {
    const publicJsonWebKey = new EllipticCurveJsonWebKey(publicParameters);
    const privateJsonWebKey = new EllipticCurveJsonWebKey(privateParameters);

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
