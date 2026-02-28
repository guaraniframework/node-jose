import { Buffer } from 'buffer';
import { AsymmetricKeyDetails, AsymmetricKeyType, KeyObject, KeyObjectType } from 'crypto';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { RsaPrivateJwk } from './rsa-private-jwk';
import { RsaPrivateJwkParams } from './rsa-private-jwk.params';

const invalidDs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidPs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidQs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidDPs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidDQs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidQIs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

const params: RsaPrivateJwkParams = {
  kty: 'RSA',
  n:
    'xjpFydzTbByzL5jhEa2yQO63dpS9d9SKaN107AR69skKiTR4uK1c4SzDt4YcurDB' +
    'yhgKNzeBo6Vq3IRrkrltp97LKWfeZdM-leGt8-UTZEWqrNf3UGOEj8kI6lbjiG-S' +
    'n_yNHcVA9qBV22norZkgXctHLeFbY6TmpD-I8_UiplZUHoc9KlYc7crCQRa-O7tK' +
    'FDULNTMjjifc0dmuYP7ZcYAZXmRmoOpQuDr8s7OZY7TAqN0btMfA7RpUCWLT6TMR' +
    'QPX8GcyTxfbkOrSTFueKMHVNdXDtl068XXJ9mkjORiEmwlzqSBoxdeLWcNf_u20S' +
    '5JG5iK0nsm1uZYu-02XN-w',
  e: 'AQAB',
  d:
    'cc2YrWia9LGRad0SMe0PrlmeeHSyRe5-u--QJcP4uF_5LYYzXIsjDJ9_iYh0S_YY' +
    'e6bLjqHOSp44OHvJqoXMX5j3-ECKnNjnUHMtRB2awXGBqBOhB8TqoQXgmXDi1jx_' +
    '6Fu8xH-vaSfpwrsN-0QzIcYHil6b8hwE0f0r6istBmL7iayJbnONp7na9ow2fUQl' +
    'nr41vsHZa4knTZ2E2kq5ntgaXlF6AIdc4DD_BZpf2alEbhQMX9T168ZsSyAs7wKS' +
    'd3ivhHRQayXEapUfZ_ykvnF4-DoVI1iRoowgZ-dlnv4Ff3YrKQ3Zv3uHJcF1BtWQ' +
    'VipOIHx4GyIc4bmTSA5PEQ',
  p:
    '-ZFuDg38cG-e5L6h1Jbn8ngifWgHx8m1gybkY7yEpU1V02fvQAMI1XG-1WpZm2xj' +
    'j218wNCj0BCEdmdBqZMk5RlzLagtfzQ3rPO-ucYPZ_SDmy8Udzr-sZLCqMFyLtxk' +
    'gMfGo4QZ6UJWYpTCCmZ92nS_pa4ePrQdlpnS4DLv_SM',
  q:
    'y1YdZtsbYfCOdsYBZrDpcvubwMN2fKRAzETYW5sqYv8XkxHG1J1zHH-zWJBQfZhT' +
    'biHPgHvoaFykEm9xhuA77RFGRXxFUrGBtfqIx_OG-kRWudmH83EyMzMoKQaW98RX' +
    'WqRO1JDlcs4_vzf_KN63zQKv5i4UdiiObQkZCYIOVUk',
  dp:
    'vqtDX-2DjgtZY_3Y-eiJMRBjmVgfiZ4r1RWjrCddWEVrauafPVKULy6F09s6tqnq' +
    'rqvBgjZk0ROtgCCHZB0NNRNqkdlJWUP1vWdDsf8FyjBfU_J2OlmSOOydV_zjVbX_' +
    '-vumYUsN2M5b3Vk1nmiLgplryhLq_JDzghnnqG6CN-0',
  dq:
    'tKczxBhSwbcpu5i70fLH1iJ5BNAkSyTbdSCNYQYAqKee2Elo76lbhixmuP6upIdb' +
    'SHO9mZd8qov0MXTV1lEOrNc2KbH5HTkb1wRZ1dwlReDFdKUxxjYBtb9zpM93_XVx' +
    'btSgPPbnBBL-S_OCPVtyzS_f-49hGoF52KHGns3v0hE',
  qi:
    'C4q9uIi-1fYhE0NTWVNzdhSi7fA3uznTWaW1X5LWBF4gBOcWvMMTfOZEaPjtY2WP' +
    'XaTWU4bdVN0GgktVLUDPLrSj533W1cOQZb_mm_7BFNrleelruT87bZhWPYQ979kl' +
    '6590ySgbH81pEM8FQW1JBATz0MYtUNZAt8N360vayE4',
};

describe('RSA Private JWK', () => {
  describe('constructor', () => {
    it.each(invalidDs)('should throw when the provided "d" is invalid.', (d) => {
      expect(() => new RsaPrivateJwk({ ...params, d })).toThrowWithMessage(
        InvalidJwkException,
        'Invalid jwk parameter "d".',
      );
    });

    it.each(invalidPs)('should throw when the provided "p" is invalid.', (p) => {
      expect(() => new RsaPrivateJwk({ ...params, p })).toThrowWithMessage(
        InvalidJwkException,
        'Invalid jwk parameter "p".',
      );
    });

    it.each(invalidQs)('should throw when the provided "q" is invalid.', (q) => {
      expect(() => new RsaPrivateJwk({ ...params, q })).toThrowWithMessage(
        InvalidJwkException,
        'Invalid jwk parameter "q".',
      );
    });

    it.each(invalidDPs)('should throw when the provided "dp" is invalid.', (dp) => {
      expect(() => new RsaPrivateJwk({ ...params, dp })).toThrowWithMessage(
        InvalidJwkException,
        'Invalid jwk parameter "dp".',
      );
    });

    it.each(invalidDQs)('should throw when the provided "dq" is invalid.', (dq) => {
      expect(() => new RsaPrivateJwk({ ...params, dq })).toThrowWithMessage(
        InvalidJwkException,
        'Invalid jwk parameter "dq".',
      );
    });

    it.each(invalidQIs)('should throw when the provided "qi" is invalid.', (qi) => {
      expect(() => new RsaPrivateJwk({ ...params, qi })).toThrowWithMessage(
        InvalidJwkException,
        'Invalid jwk parameter "qi".',
      );
    });

    it('should return a valid rsa private jwk.', () => {
      let jwk!: RsaPrivateJwk;

      expect(() => (jwk = new RsaPrivateJwk(params))).not.toThrow();

      expect(jwk).toBeInstanceOf(RsaPrivateJwk);
      expect(jwk).toMatchObject(params);

      expect(jwk.cryptoKey).toBeInstanceOf(KeyObject);
      expect(jwk.cryptoKey.type).toEqual<KeyObjectType>('private');
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
      const jwk = new RsaPrivateJwk(params);
      expect(Object.keys(jwk['getThumbprintParameters']())).toStrictEqual(['e', 'kty', 'n']);
    });
  });
});
