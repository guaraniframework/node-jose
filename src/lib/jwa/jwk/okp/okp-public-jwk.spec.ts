import { Buffer } from 'buffer';
import { AsymmetricKeyDetails, AsymmetricKeyType, KeyObject, KeyObjectType } from 'crypto';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { JwkCrv } from '../jwk-crv.type';
import { OkpPublicJwk } from './okp-public-jwk';
import { OkpPublicJwkParams } from './okp-public-jwk.params';

const invalidKtys: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], 'a'];
const invalidCrvs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], 'a'];
const invalidXs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

const params: OkpPublicJwkParams = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'aNoALKSUE1UsotuZvHUj1HEGqhpzLtsSTLmkBITDMAk',
};

describe('OKP Public JWK', () => {
  describe('constructor', () => {
    it.each(invalidKtys)('should throw when the provided "kty" is invalid.', (kty) => {
      expect(() => new OkpPublicJwk({ ...params, kty })).toThrowWithMessage(
        InvalidJwkException,
        `Invalid jwk parameter "kty". Expected "OKP", got "${String(kty)}".`,
      );
    });

    it.each(invalidCrvs)('should throw when the provided "crv" is invalid.', (crv) => {
      expect(() => new OkpPublicJwk({ ...params, crv })).toThrowWithMessage(
        InvalidJwkException,
        'Invalid jwk parameter "crv".',
      );
    });

    it.each(invalidXs)('should throw when the provided "x" is invalid.', (x) => {
      expect(() => new OkpPublicJwk({ ...params, x })).toThrowWithMessage(
        InvalidJwkException,
        'Invalid jwk parameter "x".',
      );
    });

    it('should return a valid okp public jwk.', () => {
      let jwk!: OkpPublicJwk;

      expect(() => (jwk = new OkpPublicJwk(params))).not.toThrow();

      expect(jwk).toBeInstanceOf(OkpPublicJwk);
      expect(jwk).toMatchObject(params);

      expect(jwk.cryptoKey).toBeInstanceOf(KeyObject);
      expect(jwk.cryptoKey.type).toEqual<KeyObjectType>('public');
      expect(jwk.cryptoKey.asymmetricKeyType).toEqual<AsymmetricKeyType>('ed25519');
      expect(jwk.cryptoKey.asymmetricKeyDetails).toMatchObject<AsymmetricKeyDetails>({});
      expect(jwk.cryptoKey.export({ format: 'jwk' })).toMatchObject(params);
    });
  });

  describe('supportedEllipticCurves', () => {
    it('should have ["Ed25519", "Ed448", "X25519", "X448"] as its value.', () => {
      expect(OkpPublicJwk.supportedEllipticCurves).toEqual<Extract<JwkCrv, 'Ed25519' | 'Ed448' | 'X25519' | 'X448'>[]>([
        'Ed25519',
        'Ed448',
        'X25519',
        'X448',
      ]);
    });
  });

  describe('getThumbprintParameters()', () => {
    it('should return an object with the parameters ["crv", "kty", "x"] in this exact order.', () => {
      const jwk = new OkpPublicJwk(params);
      expect(Object.keys(jwk['getThumbprintParameters']())).toStrictEqual(['crv', 'kty', 'x']);
    });
  });
});
