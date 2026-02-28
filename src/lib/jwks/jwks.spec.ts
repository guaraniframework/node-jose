import { InvalidJwksException } from '../exceptions/invalid-jwks.exception';
import { JwkNotFoundException } from '../exceptions/jwk-not-found.exception';
import { EcPrivateJwk } from '../jwa/jwk/ec/ec-private-jwk';
import { EcPrivateJwkParams } from '../jwa/jwk/ec/ec-private-jwk.params';
import { EcPublicJwk } from '../jwa/jwk/ec/ec-public-jwk';
import { EcPublicJwkParams } from '../jwa/jwk/ec/ec-public-jwk.params';
import { RsaPrivateJwk } from '../jwa/jwk/rsa/rsa-private-jwk';
import { RsaPrivateJwkParams } from '../jwa/jwk/rsa/rsa-private-jwk.params';
import { RsaPublicJwk } from '../jwa/jwk/rsa/rsa-public-jwk';
import { RsaPublicJwkParams } from '../jwa/jwk/rsa/rsa-public-jwk.params';
import { Jwk } from '../jwk/jwk';
import { Jwks } from './jwks';
import { JwksParams } from './jwks.params';

const invalidArgs: any[] = [
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
  {},
  [],
  [null],
  [true],
  [1],
  [1.2],
  [1n],
  ['a'],
  [Symbol('a')],
  [Buffer],
  [Buffer.alloc(1)],
  [() => 1],
  [{}],
  [[]],
];

const publicEcJwkParams: EcPublicJwkParams = {
  kty: 'EC',
  crv: 'P-256',
  x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
  y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
};

const privateEcJwkParams: EcPrivateJwkParams = {
  ...publicEcJwkParams,
  d: 'bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo',
};

const publicRsaJwkParameters: RsaPublicJwkParams = {
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

const privateRsaJwkParameters: RsaPrivateJwkParams = {
  ...publicRsaJwkParameters,
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

describe('JWK Set', () => {
  describe('constructor', () => {
    it.each(invalidArgs)('should throw when the provided params is invalid.', (arg) => {
      expect(() => Reflect.construct(Jwks, [arg])).toThrowWithMessage(TypeError, 'Invalid parameter "keys".');
    });

    it('should throw when a jwk set contains jwks with duplicate key identifiers.', () => {
      const jwkSetWithRepeatedKeyIdentifiers: Jwk[] = [
        new EcPublicJwk({ ...publicEcJwkParams, kid: 'key-id' }),
        new RsaPublicJwk({ ...publicRsaJwkParameters, kid: 'key-id' }),
      ];

      expect(() => new Jwks(jwkSetWithRepeatedKeyIdentifiers)).toThrow(
        new InvalidJwksException('The use of duplicate key identifiers is forbidden.'),
      );
    });

    it('should return a valid jwk set.', () => {
      let jwks!: Jwks;

      expect(() => {
        return (jwks = new Jwks([new EcPublicJwk(publicEcJwkParams), new RsaPublicJwk(publicRsaJwkParameters)]));
      }).not.toThrow();

      expect(jwks.keys).toBeArray();

      jwks.keys.forEach((jwk) => {
        expect(jwk).toBeInstanceOf(Jwk);
        expect(jwk.kid).toEqual(jwk.getThumbprint().toString('base64url'));
      });
    });
  });

  describe('find()', () => {
    const jwks = new Jwks([
      new EcPublicJwk({ ...publicEcJwkParams, kid: 'ec-key', use: 'sig' }),
      new RsaPublicJwk({ ...publicRsaJwkParameters, kid: 'rsa-key', key_ops: ['encrypt'] }),
    ]);

    it('should return null when no key matches the provided predicate.', () => {
      expect(jwks.find((key) => key.kid === 'unknown')).toBeNull();
    });

    it('should return the key that matches the provided predicate.', () => {
      expect(jwks.find((key) => key.kid === 'ec-key')).toStrictEqual(jwks.keys[0]!);
      expect(jwks.find((key) => key.key_ops?.includes('encrypt') ?? false)).toStrictEqual(jwks.keys[1]!);
    });
  });

  describe('get()', () => {
    const jwks = new Jwks([
      new EcPublicJwk({ ...publicEcJwkParams, kid: 'ec-key', use: 'sig' }),
      new RsaPublicJwk({ ...publicRsaJwkParameters, kid: 'rsa-key', key_ops: ['encrypt'] }),
    ]);

    it('should throw when no key matches the provided predicate.', () => {
      expect(() => jwks.get((key) => key.kid === 'unknown')).toThrowWithMessage(
        JwkNotFoundException,
        'No JWK matches the criteria at the JWK Set.',
      );
    });

    it('should return the key that matches the provided predicate.', () => {
      expect(jwks.get((key) => key.kid === 'ec-key')).toStrictEqual(jwks.keys[0]!);
      expect(jwks.get((key) => key.key_ops?.includes('encrypt') ?? false)).toStrictEqual(jwks.keys[1]!);
    });
  });

  describe('toJSON()', () => {
    it('should return the jwk set parameters.', () => {
      const jwks = new Jwks([
        new EcPublicJwk({ ...publicEcJwkParams, kid: 'ec-pub-key', use: 'sig' }),
        new EcPrivateJwk({ ...privateEcJwkParams, kid: 'ec-priv-key', use: 'sig' }),
        new RsaPublicJwk({ ...publicRsaJwkParameters, kid: 'rsa-pub-key', key_ops: ['encrypt'] }),
        new RsaPrivateJwk({ ...privateRsaJwkParameters, kid: 'rsa-priv-key', key_ops: ['decrypt'] }),
      ]);

      expect(jwks.toJSON()).toStrictEqual<JwksParams>({
        keys: [
          { ...publicEcJwkParams, kid: 'ec-pub-key', use: 'sig' },
          { ...privateEcJwkParams, kid: 'ec-priv-key', use: 'sig' },
          { ...publicRsaJwkParameters, kid: 'rsa-pub-key', key_ops: ['encrypt'] },
          { ...privateRsaJwkParameters, kid: 'rsa-priv-key', key_ops: ['decrypt'] },
        ],
      });
    });
  });
});
