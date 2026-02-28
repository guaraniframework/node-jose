import { Buffer } from 'buffer';
import { AsymmetricKeyDetails, AsymmetricKeyType, KeyObject, KeyObjectType } from 'crypto';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { JwkCrv } from '../jwk-crv.type';
import { EcPublicJwk } from './ec-public-jwk';
import { EcPublicJwkParams } from './ec-public-jwk.params';

const invalidKtys: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], 'a'];
const invalidCrvs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], 'a'];
const invalidXs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidYs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

const params: EcPublicJwkParams = {
  kty: 'EC',
  crv: 'P-256',
  x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
  y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
};

describe('EC Public JWK', () => {
  describe('constructor', () => {
    it.each(invalidKtys)('should throw when the provided "kty" is invalid.', (kty) => {
      expect(() => new EcPublicJwk({ ...params, kty })).toThrowWithMessage(
        InvalidJwkException,
        `Invalid jwk parameter "kty". Expected "EC", got "${String(kty)}".`,
      );
    });

    it.each(invalidCrvs)('should throw when the provided "crv" is invalid.', (crv) => {
      expect(() => new EcPublicJwk({ ...params, crv })).toThrowWithMessage(
        InvalidJwkException,
        'Invalid jwk parameter "crv".',
      );
    });

    it.each(invalidXs)('should throw when the provided "x" is invalid.', (x) => {
      expect(() => new EcPublicJwk({ ...params, x })).toThrowWithMessage(
        InvalidJwkException,
        'Invalid jwk parameter "x".',
      );
    });

    it.each(invalidYs)('should throw when the provided "y" is invalid.', (y) => {
      expect(() => new EcPublicJwk({ ...params, y })).toThrowWithMessage(
        InvalidJwkException,
        'Invalid jwk parameter "y".',
      );
    });

    it('should return a valid ec public jwk.', () => {
      let jwk!: EcPublicJwk;

      expect(() => (jwk = new EcPublicJwk(params))).not.toThrow();

      expect(jwk).toBeInstanceOf(EcPublicJwk);
      expect(jwk).toMatchObject(params);

      expect(jwk.cryptoKey).toBeInstanceOf(KeyObject);
      expect(jwk.cryptoKey.type).toEqual<KeyObjectType>('public');
      expect(jwk.cryptoKey.asymmetricKeyType).toEqual<AsymmetricKeyType>('ec');
      expect(jwk.cryptoKey.asymmetricKeyDetails).toMatchObject<AsymmetricKeyDetails>({ namedCurve: 'prime256v1' });
      expect(jwk.cryptoKey.export({ format: 'jwk' })).toMatchObject(params);
    });
  });

  describe('supportedEllipticCurves', () => {
    it('should have ["P-256", "P-384", "P-521"] as its value.', () => {
      expect(EcPublicJwk.supportedEllipticCurves).toEqual<Extract<JwkCrv, 'P-256' | 'P-384' | 'P-521'>[]>([
        'P-256',
        'P-384',
        'P-521',
      ]);
    });
  });

  describe('getThumbprintParameters()', () => {
    it('should return an object with the parameters ["crv", "kty", "x", "y"] in this exact order.', () => {
      const jwk = new EcPublicJwk(params);
      expect(Object.keys(jwk['getThumbprintParameters']())).toStrictEqual(['crv', 'kty', 'x', 'y']);
    });
  });
});
