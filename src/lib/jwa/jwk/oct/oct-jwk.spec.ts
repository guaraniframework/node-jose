import { Buffer } from 'buffer';
import { KeyObject, KeyObjectType } from 'crypto';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { OctJwk } from './oct-jwk';
import { OctJwkParams } from './oct-jwk.params';

const invalidKtys: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], 'a'];
const invalidKs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], ''];

const params: OctJwkParams = { kty: 'oct', k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ' };

describe('oct JWK', () => {
  describe('constructor', () => {
    it.each(invalidKtys)('should throw when the provided "kty" is invalid.', (kty) => {
      expect(() => new OctJwk({ ...params, kty })).toThrowWithMessage(
        InvalidJwkException,
        `Invalid jwk parameter "kty". Expected "oct", got "${String(kty)}".`,
      );
    });

    it.each(invalidKs)('should throw when the provided "k" is invalid.', (k) => {
      expect(() => new OctJwk({ ...params, k })).toThrowWithMessage(InvalidJwkException, 'Invalid jwk parameter "k".');
    });

    it('should return a valid oct jwk.', () => {
      let jwk!: OctJwk;

      expect(() => (jwk = new OctJwk(params))).not.toThrow();

      expect(jwk).toBeInstanceOf(OctJwk);
      expect(jwk).toMatchObject(params);

      expect(jwk.cryptoKey).toBeInstanceOf(KeyObject);
      expect(jwk.cryptoKey.type).toEqual<KeyObjectType>('secret');
      expect(jwk.cryptoKey.symmetricKeySize).toEqual(32);
      expect(jwk.cryptoKey.export({ format: 'jwk' })).toMatchObject(params);
    });
  });

  describe('getThumbprintParameters()', () => {
    it('should return an object with the parameters ["k", "kty"] in this exact order.', () => {
      const jwk = new OctJwk(params);
      expect(Object.keys(jwk['getThumbprintParameters']())).toStrictEqual(['k', 'kty']);
    });
  });
});
