import { Buffer } from 'buffer';
import { AsymmetricKeyDetails, AsymmetricKeyType, KeyObject, KeyObjectType } from 'crypto';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { RsaPublicJwk } from './rsa-public-jwk';
import { RsaPublicJwkParams } from './rsa-public-jwk.params';

const invalidKtys: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], 'a'];
const invalidNs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], ''];
const invalidEs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

const params: RsaPublicJwkParams = {
  kty: 'RSA',
  n:
    'xjpFydzTbByzL5jhEa2yQO63dpS9d9SKaN107AR69skKiTR4uK1c4SzDt4YcurDB' +
    'yhgKNzeBo6Vq3IRrkrltp97LKWfeZdM-leGt8-UTZEWqrNf3UGOEj8kI6lbjiG-S' +
    'n_yNHcVA9qBV22norZkgXctHLeFbY6TmpD-I8_UiplZUHoc9KlYc7crCQRa-O7tK' +
    'FDULNTMjjifc0dmuYP7ZcYAZXmRmoOpQuDr8s7OZY7TAqN0btMfA7RpUCWLT6TMR' +
    'QPX8GcyTxfbkOrSTFueKMHVNdXDtl068XXJ9mkjORiEmwlzqSBoxdeLWcNf_u20S' +
    '5JG5iK0nsm1uZYu-02XN-w',
  e: 'AQAB',
};

describe('RSA Public JWK', () => {
  describe('constructor', () => {
    it.each(invalidKtys)('should throw when the provided "kty" is invalid.', (kty) => {
      expect(() => new RsaPublicJwk({ ...params, kty })).toThrowWithMessage(
        InvalidJwkException,
        `Invalid jwk parameter "kty". Expected "RSA", got "${String(kty)}".`,
      );
    });

    it.each(invalidNs)('should throw when the provided "n" is invalid.', (n) => {
      expect(() => new RsaPublicJwk({ ...params, n })).toThrowWithMessage(
        InvalidJwkException,
        'Invalid jwk parameter "n".',
      );
    });

    it.each(invalidEs)('should throw when the provided "e" is invalid.', (e) => {
      expect(() => new RsaPublicJwk({ ...params, e })).toThrowWithMessage(
        InvalidJwkException,
        'Invalid jwk parameter "e".',
      );
    });

    it('should return a valid rsa public jwk.', () => {
      let jwk!: RsaPublicJwk;

      expect(() => (jwk = new RsaPublicJwk(params))).not.toThrow();

      expect(jwk).toBeInstanceOf(RsaPublicJwk);
      expect(jwk).toMatchObject(params);

      expect(jwk.cryptoKey).toBeInstanceOf(KeyObject);
      expect(jwk.cryptoKey.type).toEqual<KeyObjectType>('public');
      expect(jwk.cryptoKey.asymmetricKeyType).toEqual<AsymmetricKeyType>('rsa');
      expect(jwk.cryptoKey.asymmetricKeyDetails).toMatchObject<AsymmetricKeyDetails>({
        modulusLength: 2048,
        publicExponent: 0x010001n,
      });
      expect(jwk.cryptoKey.export({ format: 'jwk' })).toMatchObject(params);
    });
  });

  describe('getThumbprintParameters()', () => {
    it('should return an object with the parameters ["e", "kty", "n"] in this exact order.', () => {
      const jwk = new RsaPublicJwk(params);
      expect(Object.keys(jwk['getThumbprintParameters']())).toStrictEqual(['e', 'kty', 'n']);
    });
  });
});
