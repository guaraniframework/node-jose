import { Buffer } from 'buffer';

import { InvalidJsonWebKeySetError } from '../errors/invalid-jsonwebkeyset.error';
import { EllipticCurveJsonWebKeyParameters } from '../jwa/jwk/ec/elliptic-curve-jsonwebkey.parameters';
import { OctetKeyPairJsonWebKeyParameters } from '../jwa/jwk/okp/octet-key-pair-jsonwebkey.parameters';
import { jwk } from '../jwk';
import { JsonWebKey } from '../jwk/jsonwebkey';
import { JsonWebKeyParameters } from '../jwk/jsonwebkey.parameters';
import { create } from './create';
import { JsonWebKeySet } from './jsonwebkeyset';
import { JsonWebKeySetParameters } from './jsonwebkeyset.parameters';

const invalidKeys: any[] = [
  [[]],
  [[undefined]],
  [[null]],
  [[true]],
  [[1]],
  [[1.2]],
  [[1n]],
  [['a']],
  [[Symbol('a')]],
  [[Buffer]],
  [[Buffer.alloc(1)]],
  [[() => 1]],
  [[{}]],
  [[[]]],
];

const invalidParameters: any[] = [
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
];

const invalidJsonWebKeySetParameters: any[] = [
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
  {},
  [],
  [undefined],
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
  [[]],
  [{}],
  [{ kty: undefined }],
  [{ kty: null }],
  [{ kty: true }],
  [{ kty: 1 }],
  [{ kty: 1.2 }],
  [{ kty: 1n }],
  [{ kty: 'a' }],
  [{ kty: Symbol('a') }],
  [{ kty: Buffer }],
  [{ kty: Buffer.alloc(1) }],
  [{ kty: () => 1 }],
  [{ kty: {} }],
  [{ kty: [] }],
];

const publicEllipticCurveParameters: EllipticCurveJsonWebKeyParameters = {
  kty: 'EC',
  crv: 'P-256',
  x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
  y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
};

const publicOctetKeyPairParameters: OctetKeyPairJsonWebKeyParameters = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'aNoALKSUE1UsotuZvHUj1HEGqhpzLtsSTLmkBITDMAk',
};

describe('create()', () => {
  let duplicateKeyIdentifiers: JsonWebKey[][];

  beforeAll(async () => {
    duplicateKeyIdentifiers = [
      [
        await jwk.create({ ...publicEllipticCurveParameters, kid: 'key-id' }),
        await jwk.create({ ...publicOctetKeyPairParameters, kid: 'key-id' }),
      ],
      [await jwk.create(publicEllipticCurveParameters), await jwk.create(publicEllipticCurveParameters)],
    ];
  });

  describe('constructor', () => {
    it.each(invalidKeys)('should throw when the provided JSON Web Keys is invalid.', async (keys) => {
      await expect(create(keys)).rejects.toThrowWithMessage(TypeError, 'The provided JSON Web Keys is invalid.');
    });

    it('should throw when the provided JSON Web Keys have duplicate Keys or Identifiers.', () => {
      duplicateKeyIdentifiers.forEach(
        async (keys) =>
          await expect(create(keys)).rejects.toThrowWithMessage(
            InvalidJsonWebKeySetError,
            'The use of duplicate JSON Web Keys is forbidden.',
          ),
      );
    });

    it.each(invalidParameters)(
      'should throw when the provided JSON Web Key Set Parameters is invalid.',
      async (parameters) => {
        await expect(create(parameters)).rejects.toThrowWithMessage(
          TypeError,
          'The provided JSON Web Key Set Parameters is invalid.',
        );
      },
    );

    it.each(invalidJsonWebKeySetParameters)(
      'should throw when the provided JSON Web Key Set Parameter "keys" is invalid.',
      async (keys) => {
        await expect(create({ keys })).rejects.toThrowWithMessage(
          InvalidJsonWebKeySetError,
          'Invalid JSON Web Key Set Parameter "keys".',
        );
      },
    );

    it('should throw when the provided JSON Web Key Set have duplicate Keys or Identifiers.', () => {
      duplicateKeyIdentifiers.forEach(
        async (keys) =>
          await expect(create({ keys: keys.map((key) => key.parameters) })).rejects.toThrowWithMessage(
            InvalidJsonWebKeySetError,
            'Invalid JSON Web Key Set Parameter "keys".',
          ),
      );
    });

    it('should return a JSON Web Key Set from the provided JSON Web Keys.', async () => {
      let jsonWebKeySet!: JsonWebKeySet;

      const keys: JsonWebKey[] = [
        await jwk.create(publicEllipticCurveParameters),
        await jwk.create(publicOctetKeyPairParameters),
      ];

      await expect(async () => (jsonWebKeySet = await create(keys))).resolves.not.toThrow();

      expect(jsonWebKeySet.keys).toBeArrayOfSize(2);

      jsonWebKeySet.keys.forEach((jwk, i) => {
        expect(jwk).toBeInstanceOf(JsonWebKey);
        expect(jwk.parameters).toStrictEqual<JsonWebKeyParameters>(keys[i]!.parameters);
      });
    });

    it('should return a JSON Web Key Set from the provided JSON Web Key Set Parameters.', async () => {
      let jsonWebKeySet!: JsonWebKeySet;

      const parameters: JsonWebKeySetParameters = {
        keys: [publicEllipticCurveParameters, publicOctetKeyPairParameters],
      };

      await expect(async () => (jsonWebKeySet = await create(parameters))).resolves.not.toThrow();

      expect(jsonWebKeySet.keys).toBeArrayOfSize(2);

      jsonWebKeySet.keys.forEach((jwk, i) => {
        expect(jwk).toBeInstanceOf(JsonWebKey);
        expect(jwk.parameters).toStrictEqual<JsonWebKeyParameters>(parameters.keys[i]!);
      });
    });
  });
});
