import { Buffer } from 'buffer';
import { AsymmetricKeyDetails, AsymmetricKeyType, KeyObject, KeyObjectType } from 'crypto';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { JwkCrv } from '../jwk-crv.type';
import { EcPrivateJwk } from './ec-private-jwk';
import { EcPrivateJwkParams } from './ec-private-jwk.params';

const invalidDs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

const params: EcPrivateJwkParams = {
  kty: 'EC',
  crv: 'P-256',
  x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
  y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
  d: 'bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo',
};

describe('EC Private JWK', () => {
  describe('constructor', () => {
    it.each(invalidDs)('should throw when the provided "d" is invalid.', (d) => {
      expect(() => new EcPrivateJwk({ ...params, d })).toThrowWithMessage(
        InvalidJwkException,
        'Invalid jwk parameter "d".',
      );
    });

    it('should return a valid ec private jwk.', () => {
      let jwk!: EcPrivateJwk;

      expect(() => (jwk = new EcPrivateJwk(params))).not.toThrow();

      expect(jwk).toBeInstanceOf(EcPrivateJwk);
      expect(jwk).toMatchObject(params);

      expect(jwk.cryptoKey).toBeInstanceOf(KeyObject);
      expect(jwk.cryptoKey.type).toEqual<KeyObjectType>('private');
      expect(jwk.cryptoKey.asymmetricKeyType).toEqual<AsymmetricKeyType>('ec');
      expect(jwk.cryptoKey.asymmetricKeyDetails).toMatchObject<AsymmetricKeyDetails>({ namedCurve: 'prime256v1' });
      expect(jwk.cryptoKey.export({ format: 'jwk' })).toMatchObject(params);
    });
  });

  describe('supportedEllipticCurves', () => {
    it('should have ["P-256", "P-384", "P-521"] as its value.', () => {
      expect(EcPrivateJwk.supportedEllipticCurves).toEqual<Extract<JwkCrv, 'P-256' | 'P-384' | 'P-521'>[]>([
        'P-256',
        'P-384',
        'P-521',
      ]);
    });
  });

  describe('getThumbprintParameters()', () => {
    it('should return an object with the parameters ["crv", "kty", "x", "y"] in this exact order.', () => {
      const jwk = new EcPrivateJwk(params);
      expect(Object.keys(jwk['getThumbprintParameters']())).toStrictEqual(['crv', 'kty', 'x', 'y']);
    });
  });
});
