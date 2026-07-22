import { Buffer } from 'buffer';
import crypto, { KeyObject } from 'crypto';

import { InvalidJsonWebKeyError } from '../../../errors/invalid-jsonwebkey.error';
import { GenerateRsaJsonWebKeyOptions } from './generate-rsa-jsonwebkey.options';
import { RsaJsonWebKey } from './rsa.jsonwebkey';
import { RsaJsonWebKeyParameters } from './rsa-jsonwebkey.parameters';

const invalidNs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], ''];
const invalidEs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], ''];
const invalidDs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], ''];
const invalidPs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], ''];
const invalidQs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], ''];

const invalidDPs: any[] = [
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
];

const invalidDQs: any[] = [
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
];

const invalidQIs: any[] = [
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
];

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

const invalidModuli: any[] = [
  undefined,
  null,
  true,
  1.2,
  1n,
  'a',
  Symbol('foo'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  2047,
];

const invalidPublicExponents: any[] = [
  null,
  true,
  1.2,
  1n,
  'a',
  Symbol('foo'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  -1,
  0,
];

describe('RSA JSON Web Key', () => {
  const publicParameters: RsaJsonWebKeyParameters = {
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

  const privateParameters: RsaJsonWebKeyParameters = {
    ...publicParameters,
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

  const options: GenerateRsaJsonWebKeyOptions = { modulus: 2048 };
  const optionsWithPublicExponent: GenerateRsaJsonWebKeyOptions = { modulus: 2048, publicExponent: 0x010001 };

  beforeEach(() => {
    jest.restoreAllMocks();
  });

  describe('constructor', () => {
    it.each(invalidNs)('should throw when the provided JSON Web Key Parameter "n" is invalid.', (n) => {
      expect(() => new RsaJsonWebKey({ ...publicParameters, n })).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'Invalid JSON Web Key Parameter "n".',
      );
    });

    it.each(invalidEs)('should throw when the provided JSON Web Key Parameter "e" is invalid.', (e) => {
      expect(() => new RsaJsonWebKey({ ...publicParameters, e })).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'Invalid JSON Web Key Parameter "e".',
      );
    });

    it.each(invalidDs)('should throw when the provided JSON Web Key Parameter "d" is invalid.', (d) => {
      expect(() => new RsaJsonWebKey({ ...publicParameters, d })).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'Invalid JSON Web Key Parameter "d".',
      );
    });

    it.each(invalidPs)('should throw when the provided JSON Web Key Parameter "p" is invalid.', (p) => {
      expect(() => new RsaJsonWebKey({ ...privateParameters, p })).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'Invalid JSON Web Key Parameter "p".',
      );
    });

    it.each(invalidQs)('should throw when the provided JSON Web Key Parameter "q" is invalid.', (q) => {
      expect(() => new RsaJsonWebKey({ ...privateParameters, q })).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'Invalid JSON Web Key Parameter "q".',
      );
    });

    it.each(invalidDPs)('should throw when the provided JSON Web Key Parameter "dp" is invalid.', (dp) => {
      expect(() => new RsaJsonWebKey({ ...privateParameters, dp })).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'Invalid JSON Web Key Parameter "dp".',
      );
    });

    it.each(invalidDQs)('should throw when the provided JSON Web Key Parameter "dq" is invalid.', (dq) => {
      expect(() => new RsaJsonWebKey({ ...privateParameters, dq })).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'Invalid JSON Web Key Parameter "dq".',
      );
    });

    it.each(invalidQIs)('should throw when the provided JSON Web Key Parameter "qi" is invalid.', (qi) => {
      expect(() => new RsaJsonWebKey({ ...privateParameters, qi })).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'Invalid JSON Web Key Parameter "qi".',
      );
    });

    it('should return a Public RSA JSON Web Key.', () => {
      let jwk!: RsaJsonWebKey;

      expect(() => (jwk = new RsaJsonWebKey(publicParameters))).not.toThrow();

      expect(jwk.parameters).toStrictEqual(publicParameters);

      expect(jwk.cryptoKey).toBeInstanceOf(KeyObject);
      expect(jwk.cryptoKey.export({ format: 'jwk' })).toStrictEqual(publicParameters);
    });

    it('should return a Private RSA JSON Web Key.', () => {
      let jwk!: RsaJsonWebKey;

      expect(() => (jwk = new RsaJsonWebKey(privateParameters))).not.toThrow();

      expect(jwk.parameters).toStrictEqual(privateParameters);

      expect(jwk.cryptoKey).toBeInstanceOf(KeyObject);
      expect(jwk.cryptoKey.export({ format: 'jwk' })).toStrictEqual(privateParameters);
    });
  });

  describe('generate()', () => {
    it.each(invalidGenerateOptions)('should throw when the provided options is invalid.', async (options) => {
      await expect(RsaJsonWebKey.generate(options)).rejects.toThrowWithMessage(
        TypeError,
        'The provided options is invalid.',
      );
    });

    it.each(invalidModuli)('should throw when the provided Modulus is invalid.', async (modulus) => {
      await expect(RsaJsonWebKey.generate({ modulus })).rejects.toThrowWithMessage(
        TypeError,
        'The provided Modulus is invalid.',
      );
    });

    it.each(invalidPublicExponents)(
      'should throw when the provided Public Exponent is invalid.',
      async (publicExponent) => {
        await expect(RsaJsonWebKey.generate({ ...options, publicExponent })).rejects.toThrowWithMessage(
          TypeError,
          'The provided Public Exponent is invalid.',
        );
      },
    );

    it('should return the generated RSA Crypto Key.', async () => {
      let cryptoKey!: KeyObject;

      await expect(async () => (cryptoKey = await RsaJsonWebKey.generate(options))).resolves.not.toThrow();

      expect(cryptoKey).toBeInstanceOf(KeyObject);
      expect(cryptoKey.export({ format: 'jwk' })).toMatchObject<RsaJsonWebKeyParameters>({
        kty: 'RSA',
        n: expect.toBeString(),
        e: 'AQAB',
        d: expect.toBeString(),
        p: expect.toBeString(),
        q: expect.toBeString(),
        dp: expect.toBeString(),
        dq: expect.toBeString(),
        qi: expect.toBeString(),
      });
    });

    it('should return the generated RSA Crypto Key with a custom Public Exponent.', async () => {
      let cryptoKey!: KeyObject;

      await expect(
        async () => (cryptoKey = await RsaJsonWebKey.generate(optionsWithPublicExponent)),
      ).resolves.not.toThrow();

      expect(cryptoKey).toBeInstanceOf(KeyObject);
      expect(cryptoKey.export({ format: 'jwk' })).toMatchObject<RsaJsonWebKeyParameters>({
        kty: 'RSA',
        n: expect.toBeString(),
        e: 'AQAB',
        d: expect.toBeString(),
        p: expect.toBeString(),
        q: expect.toBeString(),
        dp: expect.toBeString(),
        dq: expect.toBeString(),
        qi: expect.toBeString(),
      });
    });
  });

  describe('getThumbprint()', () => {
    it('should return the Thumbprint of the Public JSON Web Key.', () => {
      const jwk = new RsaJsonWebKey(publicParameters);
      const createHashSpy = jest.spyOn(crypto, 'createHash');

      expect(jwk.getThumbprint().toString('base64url')).toStrictEqual('OLDDm37M8_sU1nFYsM4WKaWkLQbgHUMnw3qM2askkGU');
      expect(createHashSpy).toHaveBeenCalledOnce();
    });

    it('should return the Thumbprint of the Private JSON Web Key.', () => {
      const jwk = new RsaJsonWebKey(privateParameters);
      const createHashSpy = jest.spyOn(crypto, 'createHash');

      expect(jwk.getThumbprint().toString('base64url')).toStrictEqual('OLDDm37M8_sU1nFYsM4WKaWkLQbgHUMnw3qM2askkGU');
      expect(createHashSpy).toHaveBeenCalledOnce();
    });
  });

  describe('getThumbprintURI()', () => {
    it('should return the Thumbprint of the Public JSON Web Key.', () => {
      const jwk = new RsaJsonWebKey(publicParameters);

      expect(jwk.getThumbprintURI()).toStrictEqual(
        'urn:ietf:params:oauth:jwk-thumbprint:sha-256:OLDDm37M8_sU1nFYsM4WKaWkLQbgHUMnw3qM2askkGU',
      );
    });

    it('should return the Thumbprint of the Private JSON Web Key.', () => {
      const jwk = new RsaJsonWebKey(privateParameters);

      expect(jwk.getThumbprintURI()).toStrictEqual(
        'urn:ietf:params:oauth:jwk-thumbprint:sha-256:OLDDm37M8_sU1nFYsM4WKaWkLQbgHUMnw3qM2askkGU',
      );
    });
  });

  describe('toJSON()', () => {
    const publicJwk = new RsaJsonWebKey(publicParameters);
    const privateJwk = new RsaJsonWebKey(privateParameters);

    it('should return the Public JSON Web Key Parameters of the Public Key when exportPrivate is undefined.', () => {
      expect(publicJwk.toJSON()).toStrictEqual(publicParameters);
    });

    it('should return the Public JSON Web Key Parameters of the Public Key when exportPrivate is false.', () => {
      expect(publicJwk.toJSON(false)).toStrictEqual(publicParameters);
    });

    it('should return the Public JSON Web Key Parameters of the Public Key when exportPrivate is true.', () => {
      expect(publicJwk.toJSON(true)).toStrictEqual(publicParameters);
    });

    it('should return the Public JSON Web Key Parameters of the Private Key when exportPrivate is undefined.', () => {
      expect(privateJwk.toJSON()).toStrictEqual(publicParameters);
    });

    it('should return the Public JSON Web Key Parameters of the Private Key when exportPrivate is false.', () => {
      expect(privateJwk.toJSON(false)).toStrictEqual(publicParameters);
    });

    it('should return the Private JSON Web Key Parameters of the Private Key when exportPrivate is true.', () => {
      expect(privateJwk.toJSON(true)).toStrictEqual(privateParameters);
    });
  });
});
