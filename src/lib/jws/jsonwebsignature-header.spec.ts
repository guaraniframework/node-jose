import { Buffer } from 'buffer';

import { InvalidJoseHeaderError } from '../errors/invalid-jose-header.error';
import { DigitalSignatureAlgorithm } from '../jwa/jws/digital-signature-algorithm.type';
import { JsonWebSignatureDigitalSignatureBackend } from '../jwa/jws/jsonwebsignature-digital-signature.backend';
import { JsonWebSignatureHeader } from './jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from './jsonwebsignature-header.parameters';

const invalidAlgs: any[] = [
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
  'a',
];

const invalidB64s: any[] = [undefined, null, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

const invalidIsJoseHeaderParametersData: any[] = [
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
  { alg: undefined },
  { alg: null },
  { alg: true },
  { alg: 1 },
  { alg: 1.2 },
  { alg: 1n },
  { alg: Symbol('a') },
  { alg: Buffer },
  { alg: Buffer.alloc(0) },
  { alg: () => 1 },
  { alg: {} },
  { alg: [] },
  { alg: 'A128KW' },
];

const headerAlgorithms: [DigitalSignatureAlgorithm][] = [
  ['ES256'],
  ['ES256K'],
  ['ES384'],
  ['ES512'],
  ['EdDSA'],
  ['HS256'],
  ['HS384'],
  ['HS512'],
  ['PS256'],
  ['PS384'],
  ['PS512'],
  ['RS256'],
  ['RS384'],
  ['RS512'],
  ['none'],
];

describe('JSON Web Signature Header', () => {
  const parameters: JsonWebSignatureHeaderParameters = { alg: 'ES256' };

  describe('constructor', () => {
    it.each(invalidAlgs)('should throw when the provided JOSE Header Parameter "alg" is invalid.', (alg) => {
      expect(() => new JsonWebSignatureHeader({ ...parameters, alg })).toThrowWithMessage(
        InvalidJoseHeaderError,
        'Invalid JOSE Header Parameter "alg".',
      );
    });

    it.each(invalidB64s)('should throw when the provided JOSE Header Parameter "b64" is invalid.', (b64) => {
      expect(() => new JsonWebSignatureHeader({ ...parameters, b64 })).toThrowWithMessage(
        InvalidJoseHeaderError,
        'Invalid JOSE Header Parameter "b64".',
      );
    });

    it('should throw when the JOSE Header Parameter "b64" is not present at the JOSE Header Parameter "crit".', () => {
      expect(() => new JsonWebSignatureHeader({ ...parameters, b64: false })).toThrowWithMessage(
        InvalidJoseHeaderError,
        'Invalid JOSE Header Parameter "b64".',
      );
    });

    it.each(headerAlgorithms)('should return a JSON Web Signature Header.', (alg) => {
      let header!: JsonWebSignatureHeader;

      expect(() => (header = new JsonWebSignatureHeader({ alg }))).not.toThrow();

      expect(header.digitalSignatureBackend).toBeInstanceOf(JsonWebSignatureDigitalSignatureBackend);
      expect(header.digitalSignatureBackend['algorithm']).toBe(alg);

      expect(header.certificateChain).toBeNull();
      expect(header.jsonWebKey).toBeNull();
      expect(header.parameters).toStrictEqual({ alg });
    });

    it.each(headerAlgorithms)('should return a JSON Web Signature Header with the "b64" extension.', (alg) => {
      let header!: JsonWebSignatureHeader;

      expect(() => (header = new JsonWebSignatureHeader({ alg, b64: false, crit: ['b64'] }))).not.toThrow();

      expect(header.digitalSignatureBackend).toBeInstanceOf(JsonWebSignatureDigitalSignatureBackend);
      expect(header.digitalSignatureBackend['algorithm']).toBe(alg);

      expect(header.certificateChain).toBeNull();
      expect(header.jsonWebKey).toBeNull();
      expect(header.parameters).toStrictEqual({ alg, b64: false, crit: ['b64'] });
    });
  });

  describe('isJoseHeaderParameters()', () => {
    it.each(invalidIsJoseHeaderParametersData)(
      'should return false when the provided JOSE Header Parameters is invalid.',
      (data) => {
        expect(JsonWebSignatureHeader.isJoseHeaderParameters(data)).toBeFalse();
      },
    );

    it('should return true when the provided JOSE Header Parameters is valid.', () => {
      expect(JsonWebSignatureHeader.isJoseHeaderParameters(parameters)).toBeTrue();
    });
  });
});
