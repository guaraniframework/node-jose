import { InvalidJsonWebKeyError } from '../errors/invalid-jsonwebkey.error';
import { EllipticCurveJsonWebKeyParameters } from '../jwa/jwk/ec/elliptic-curve-jsonwebkey.parameters';
import { OctetKeyPairJsonWebKeyParameters } from '../jwa/jwk/okp/octet-key-pair-jsonwebkey.parameters';
import { create } from '../jwk/create';
import { JsonWebKeySet } from './jsonwebkeyset';
import { JsonWebKeySetParameters } from './jsonwebkeyset.parameters';

describe('JSON Web Key Set', () => {
  const publicEllipticCurveParameters: EllipticCurveJsonWebKeyParameters = {
    kty: 'EC',
    crv: 'P-256',
    x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
    y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
  };

  const privateEllipticCurveParameters: EllipticCurveJsonWebKeyParameters = {
    ...publicEllipticCurveParameters,
    d: 'bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo',
  };

  const publicOctetKeyPairParameters: OctetKeyPairJsonWebKeyParameters = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: 'aNoALKSUE1UsotuZvHUj1HEGqhpzLtsSTLmkBITDMAk',
  };

  const privateOctetKeyPairParameters: OctetKeyPairJsonWebKeyParameters = {
    ...publicOctetKeyPairParameters,
    d: 'tccuS3jrlRwPaNsn2YxpUuMCqvnlsIgy_T0S7qVmo-A',
  };

  describe('find()', () => {
    let jsonWebKeySet: JsonWebKeySet;

    beforeAll(async () => {
      jsonWebKeySet = new JsonWebKeySet([
        await create({ ...publicEllipticCurveParameters, kid: 'ec-key', use: 'sig' }),
        await create({ ...publicOctetKeyPairParameters, kid: 'rsa-key', key_ops: ['encrypt'] }),
      ]);
    });

    it('should return null when no JSON Web Key matches the provided predicate.', () => {
      expect(jsonWebKeySet.find((key) => key.kid === 'unknown')).toBeNull();
    });

    it('should return the JSON Web Key that matches the provided predicate.', () => {
      expect(jsonWebKeySet.find((key) => key.kid === 'ec-key')).toStrictEqual(jsonWebKeySet.keys[0]!);
      expect(jsonWebKeySet.find((key) => key.key_ops?.includes('encrypt') ?? false)).toStrictEqual(
        jsonWebKeySet.keys[1]!,
      );
    });
  });

  describe('get()', () => {
    let jsonWebKeySet: JsonWebKeySet;

    beforeAll(async () => {
      jsonWebKeySet = new JsonWebKeySet([
        await create({ ...publicEllipticCurveParameters, kid: 'ec-key', use: 'sig' }),
        await create({ ...publicOctetKeyPairParameters, kid: 'rsa-key', key_ops: ['encrypt'] }),
      ]);
    });

    it('should throw when no JSON Web Key matches the provided predicate.', () => {
      expect(() => jsonWebKeySet.get((key) => key.kid === 'unknown')).toThrowWithMessage(
        InvalidJsonWebKeyError,
        'No JSON Web Key matches the criteria in the JSON Web Key Set.',
      );
    });

    it('should return the JSON Web Key that matches the provided predicate.', () => {
      expect(jsonWebKeySet.get((key) => key.kid === 'ec-key')).toStrictEqual(jsonWebKeySet.keys[0]!);
      expect(jsonWebKeySet.get((key) => key.key_ops?.includes('encrypt') ?? false)).toStrictEqual(
        jsonWebKeySet.keys[1]!,
      );
    });
  });

  describe('toJSON()', () => {
    it('should return the Public JSON Web Key Set Parameters when exportPrivate is undefined.', async () => {
      const jsonWebKeySet = new JsonWebKeySet([
        await create({ ...publicEllipticCurveParameters, kid: 'ec-pub-key', use: 'sig' }),
        await create({ ...privateEllipticCurveParameters, kid: 'ec-priv-key', use: 'sig' }),
        await create({ ...publicOctetKeyPairParameters, kid: 'okp-pub-key', key_ops: ['encrypt'] }),
        await create({ ...privateOctetKeyPairParameters, kid: 'okp-priv-key', key_ops: ['decrypt'] }),
      ]);

      expect(jsonWebKeySet.toJSON()).toStrictEqual<JsonWebKeySetParameters>({
        keys: [
          { ...publicEllipticCurveParameters, kid: 'ec-pub-key', use: 'sig' },
          { ...publicEllipticCurveParameters, kid: 'ec-priv-key', use: 'sig' },
          { ...publicOctetKeyPairParameters, kid: 'okp-pub-key', key_ops: ['encrypt'] },
          { ...publicOctetKeyPairParameters, kid: 'okp-priv-key', key_ops: ['decrypt'] },
        ],
      });
    });

    it('should return the Public JSON Web Key Set Parameters when exportPrivate is false.', async () => {
      const jsonWebKeySet = new JsonWebKeySet([
        await create({ ...publicEllipticCurveParameters, kid: 'ec-pub-key', use: 'sig' }),
        await create({ ...privateEllipticCurveParameters, kid: 'ec-priv-key', use: 'sig' }),
        await create({ ...publicOctetKeyPairParameters, kid: 'okp-pub-key', key_ops: ['encrypt'] }),
        await create({ ...privateOctetKeyPairParameters, kid: 'okp-priv-key', key_ops: ['decrypt'] }),
      ]);

      expect(jsonWebKeySet.toJSON(false)).toStrictEqual<JsonWebKeySetParameters>({
        keys: [
          { ...publicEllipticCurveParameters, kid: 'ec-pub-key', use: 'sig' },
          { ...publicEllipticCurveParameters, kid: 'ec-priv-key', use: 'sig' },
          { ...publicOctetKeyPairParameters, kid: 'okp-pub-key', key_ops: ['encrypt'] },
          { ...publicOctetKeyPairParameters, kid: 'okp-priv-key', key_ops: ['decrypt'] },
        ],
      });
    });

    it('should return the Private JSON Web Key Set Parameters when exportPrivate is true.', async () => {
      const jsonWebKeySet = new JsonWebKeySet([
        await create({ ...publicEllipticCurveParameters, kid: 'ec-pub-key', use: 'sig' }),
        await create({ ...privateEllipticCurveParameters, kid: 'ec-priv-key', use: 'sig' }),
        await create({ ...publicOctetKeyPairParameters, kid: 'okp-pub-key', key_ops: ['encrypt'] }),
        await create({ ...privateOctetKeyPairParameters, kid: 'okp-priv-key', key_ops: ['decrypt'] }),
      ]);

      expect(jsonWebKeySet.toJSON(true)).toStrictEqual<JsonWebKeySetParameters>({
        keys: [
          { ...publicEllipticCurveParameters, kid: 'ec-pub-key', use: 'sig' },
          { ...privateEllipticCurveParameters, kid: 'ec-priv-key', use: 'sig' },
          { ...publicOctetKeyPairParameters, kid: 'okp-pub-key', key_ops: ['encrypt'] },
          { ...privateOctetKeyPairParameters, kid: 'okp-priv-key', key_ops: ['decrypt'] },
        ],
      });
    });
  });
});
