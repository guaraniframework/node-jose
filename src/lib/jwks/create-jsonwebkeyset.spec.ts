import { Buffer } from 'buffer';

import { InvalidJsonWebKeySetError } from '../errors/invalid-jsonwebkeyset.error';
import { EllipticCurveJsonWebKeyParameters } from '../jwa/jwk/ec/elliptic-curve-jsonwebkey.parameters';
import { OctetKeyPairJsonWebKeyParameters } from '../jwa/jwk/okp/octet-key-pair-jsonwebkey.parameters';
import { createJsonWebKey } from '../jwk/create-jsonwebkey';
import { JsonWebKey } from '../jwk/jsonwebkey';
import { JsonWebKeyParameters } from '../jwk/jsonwebkey.parameters';
import { createJsonWebKeySet } from './create-jsonwebkeyset';
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

describe('createJsonWebKeySet()', () => {
  let duplicateKeyIdentifiers: JsonWebKey[][];

  beforeAll(async () => {
    duplicateKeyIdentifiers = [
      [
        await createJsonWebKey({ ...publicEllipticCurveParameters, kid: 'key-id' }),
        await createJsonWebKey({ ...publicOctetKeyPairParameters, kid: 'key-id' }),
      ],
      [await createJsonWebKey(publicEllipticCurveParameters), await createJsonWebKey(publicEllipticCurveParameters)],
    ];
  });

  describe('constructor', () => {
    it.each(invalidKeys)('should throw when the provided JSON Web Keys is invalid.', async (keys) => {
      await expect(createJsonWebKeySet(keys)).rejects.toThrowWithMessage(
        TypeError,
        'The provided JSON Web Keys is invalid.',
      );
    });

    it('should throw when the provided JSON Web Keys have duplicate Keys or Identifiers.', () => {
      duplicateKeyIdentifiers.forEach(
        async (keys) =>
          await expect(createJsonWebKeySet(keys)).rejects.toThrowWithMessage(
            InvalidJsonWebKeySetError,
            'The use of duplicate JSON Web Keys is forbidden.',
          ),
      );
    });

    it.each(invalidParameters)(
      'should throw when the provided JSON Web Key Set Parameters is invalid.',
      async (parameters) => {
        await expect(createJsonWebKeySet(parameters)).rejects.toThrowWithMessage(
          TypeError,
          'The provided JSON Web Key Set Parameters is invalid.',
        );
      },
    );

    it.each(invalidJsonWebKeySetParameters)(
      'should throw when the provided JSON Web Key Set Parameter "keys" is invalid.',
      async (keys) => {
        await expect(createJsonWebKeySet({ keys })).rejects.toThrowWithMessage(
          InvalidJsonWebKeySetError,
          'Invalid JSON Web Key Set Parameter "keys".',
        );
      },
    );

    it('should throw when the provided JSON Web Key Set have duplicate Keys or Identifiers.', () => {
      duplicateKeyIdentifiers.forEach(
        async (keys) =>
          await expect(createJsonWebKeySet({ keys: keys.map((key) => key.parameters) })).rejects.toThrowWithMessage(
            InvalidJsonWebKeySetError,
            'Invalid JSON Web Key Set Parameter "keys".',
          ),
      );
    });

    it('should return a JSON Web Key Set from the provided JSON Web Keys.', async () => {
      let jwkSet!: JsonWebKeySet;

      const keys: JsonWebKey[] = [
        await createJsonWebKey(publicEllipticCurveParameters),
        await createJsonWebKey(publicOctetKeyPairParameters),
      ];

      await expect(async () => (jwkSet = await createJsonWebKeySet(keys))).resolves.not.toThrow();

      expect(jwkSet.keys).toBeArrayOfSize(2);

      jwkSet.keys.forEach((jwk, i) => {
        expect(jwk).toBeInstanceOf(JsonWebKey);
        expect(jwk.parameters).toStrictEqual<JsonWebKeyParameters>(keys[i]!.parameters);
      });
    });

    it('should return a JSON Web Key Set from the provided JSON Web Key Set Parameters.', async () => {
      let jwkSet!: JsonWebKeySet;

      const parameters: JsonWebKeySetParameters = {
        keys: [publicEllipticCurveParameters, publicOctetKeyPairParameters],
      };

      await expect(async () => (jwkSet = await createJsonWebKeySet(parameters))).resolves.not.toThrow();

      expect(jwkSet.keys).toBeArrayOfSize(2);

      jwkSet.keys.forEach((jwk, i) => {
        expect(jwk).toBeInstanceOf(JsonWebKey);
        expect(jwk.parameters).toStrictEqual<JsonWebKeyParameters>(parameters.keys[i]!);
      });
    });
  });
});
