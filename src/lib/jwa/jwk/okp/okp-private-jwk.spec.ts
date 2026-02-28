import { Buffer } from 'buffer';
import { AsymmetricKeyDetails, AsymmetricKeyType, KeyObject, KeyObjectType } from 'crypto';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { JwkCrv } from '../jwk-crv.type';
import { OkpPrivateJwk } from './okp-private-jwk';
import { OkpPrivateJwkParams } from './okp-private-jwk.params';

const invalidDs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

const params: OkpPrivateJwkParams = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'aNoALKSUE1UsotuZvHUj1HEGqhpzLtsSTLmkBITDMAk',
  d: 'tccuS3jrlRwPaNsn2YxpUuMCqvnlsIgy_T0S7qVmo-A',
};

describe('OKP Private JWK', () => {
  describe('constructor', () => {
    it.each(invalidDs)('should throw when the provided "d" is invalid.', (d) => {
      expect(() => new OkpPrivateJwk({ ...params, d })).toThrowWithMessage(
        InvalidJwkException,
        'Invalid jwk parameter "d".',
      );
    });

    it('should return a valid okp private jwk.', () => {
      let jwk!: OkpPrivateJwk;

      expect(() => (jwk = new OkpPrivateJwk(params))).not.toThrow();

      expect(jwk).toBeInstanceOf(OkpPrivateJwk);
      expect(jwk).toMatchObject(params);

      expect(jwk.cryptoKey).toBeInstanceOf(KeyObject);
      expect(jwk.cryptoKey.type).toEqual<KeyObjectType>('private');
      expect(jwk.cryptoKey.asymmetricKeyType).toEqual<AsymmetricKeyType>('ed25519');
      expect(jwk.cryptoKey.asymmetricKeyDetails).toMatchObject<AsymmetricKeyDetails>({});
      expect(jwk.cryptoKey.export({ format: 'jwk' })).toMatchObject(params);
    });
  });

  describe('supportedEllipticCurves', () => {
    it('should have ["Ed25519", "Ed448", "X25519", "X448"] as its value.', () => {
      expect(OkpPrivateJwk.supportedEllipticCurves).toEqual<Extract<JwkCrv, 'Ed25519' | 'Ed448' | 'X25519' | 'X448'>[]>(
        ['Ed25519', 'Ed448', 'X25519', 'X448'],
      );
    });
  });

  describe('getThumbprintParameters()', () => {
    it('should return an object with the parameters ["crv", "kty", "x"] in this exact order.', () => {
      const jwk = new OkpPrivateJwk(params);
      expect(Object.keys(jwk['getThumbprintParameters']())).toStrictEqual(['crv', 'kty', 'x']);
    });
  });
});
