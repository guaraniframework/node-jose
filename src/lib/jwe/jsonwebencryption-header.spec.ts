import { Buffer } from 'buffer';

import { InvalidJoseHeaderError } from '../errors/invalid-jose-header.error';
import { JsonWebEncryptionKeyManagementBackend } from '../jwa/jwe/alg/jsonwebencryption-key-management.backend';
import { KeyManagementAlgorithm } from '../jwa/jwe/alg/key-management-algorithm.type';
import { ContentEncryptionAlgorithm } from '../jwa/jwe/enc/content-encryption-algorithm.type';
import { JsonWebEncryptionContentEncryptionBackend } from '../jwa/jwe/enc/jsonwebencryption-content-encryption.backend';
import { CompressionAlgorithm } from '../jwa/jwe/zip/compression-algorithm.type';
import { JsonWebEncryptionCompressionBackend } from '../jwa/jwe/zip/jsonwebencryption-compression.backend';
import { JsonWebEncryptionHeader } from './jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from './jsonwebencryption-header.parameters';

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

const invalidEncs: any[] = [
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

const invalidZips: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], 'a'];

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
  { alg: 'HS256' },
  { alg: 'A128KW', enc: undefined },
  { alg: 'A128KW', enc: null },
  { alg: 'A128KW', enc: true },
  { alg: 'A128KW', enc: 1 },
  { alg: 'A128KW', enc: 1.2 },
  { alg: 'A128KW', enc: 1n },
  { alg: 'A128KW', enc: Symbol('a') },
  { alg: 'A128KW', enc: Buffer },
  { alg: 'A128KW', enc: Buffer.alloc(0) },
  { alg: 'A128KW', enc: () => 1 },
  { alg: 'A128KW', enc: {} },
  { alg: 'A128KW', enc: [] },
  { alg: 'A128KW', enc: 'a' },
  { alg: 'A128KW', enc: 'A128CBC-HS256', zip: null },
  { alg: 'A128KW', enc: 'A128CBC-HS256', zip: true },
  { alg: 'A128KW', enc: 'A128CBC-HS256', zip: 1 },
  { alg: 'A128KW', enc: 'A128CBC-HS256', zip: 1.2 },
  { alg: 'A128KW', enc: 'A128CBC-HS256', zip: 1n },
  { alg: 'A128KW', enc: 'A128CBC-HS256', zip: Symbol('a') },
  { alg: 'A128KW', enc: 'A128CBC-HS256', zip: Buffer },
  { alg: 'A128KW', enc: 'A128CBC-HS256', zip: Buffer.alloc(0) },
  { alg: 'A128KW', enc: 'A128CBC-HS256', zip: () => 1 },
  { alg: 'A128KW', enc: 'A128CBC-HS256', zip: {} },
  { alg: 'A128KW', enc: 'A128CBC-HS256', zip: [] },
  { alg: 'A128KW', enc: 'A128CBC-HS256', zip: 'a' },
];

const headerAlgorithms: [KeyManagementAlgorithm, ContentEncryptionAlgorithm][] = [
  ['A128GCMKW', 'A128CBC-HS256'],
  ['A128KW', 'A128CBC-HS256'],
  ['A192GCMKW', 'A128CBC-HS256'],
  ['A192KW', 'A128CBC-HS256'],
  ['A256GCMKW', 'A128CBC-HS256'],
  ['A256KW', 'A128CBC-HS256'],
  ['ECDH-ES', 'A128CBC-HS256'],
  ['ECDH-ES+A128KW', 'A128CBC-HS256'],
  ['ECDH-ES+A192KW', 'A128CBC-HS256'],
  ['ECDH-ES+A256KW', 'A128CBC-HS256'],
  ['PBES2-HS256+A128KW', 'A128CBC-HS256'],
  ['PBES2-HS384+A192KW', 'A128CBC-HS256'],
  ['PBES2-HS512+A256KW', 'A128CBC-HS256'],
  ['RSA-OAEP', 'A128CBC-HS256'],
  ['RSA-OAEP-256', 'A128CBC-HS256'],
  ['RSA-OAEP-384', 'A128CBC-HS256'],
  ['RSA-OAEP-512', 'A128CBC-HS256'],
  ['RSA1_5', 'A128CBC-HS256'],
  ['dir', 'A128CBC-HS256'],
  ['A128GCMKW', 'A128GCM'],
  ['A128KW', 'A128GCM'],
  ['A192GCMKW', 'A128GCM'],
  ['A192KW', 'A128GCM'],
  ['A256GCMKW', 'A128GCM'],
  ['A256KW', 'A128GCM'],
  ['ECDH-ES', 'A128GCM'],
  ['ECDH-ES+A128KW', 'A128GCM'],
  ['ECDH-ES+A192KW', 'A128GCM'],
  ['ECDH-ES+A256KW', 'A128GCM'],
  ['PBES2-HS256+A128KW', 'A128GCM'],
  ['PBES2-HS384+A192KW', 'A128GCM'],
  ['PBES2-HS512+A256KW', 'A128GCM'],
  ['RSA-OAEP', 'A128GCM'],
  ['RSA-OAEP-256', 'A128GCM'],
  ['RSA-OAEP-384', 'A128GCM'],
  ['RSA-OAEP-512', 'A128GCM'],
  ['RSA1_5', 'A128GCM'],
  ['dir', 'A128GCM'],
  ['A128GCMKW', 'A192CBC-HS384'],
  ['A128KW', 'A192CBC-HS384'],
  ['A192GCMKW', 'A192CBC-HS384'],
  ['A192KW', 'A192CBC-HS384'],
  ['A256GCMKW', 'A192CBC-HS384'],
  ['A256KW', 'A192CBC-HS384'],
  ['ECDH-ES', 'A192CBC-HS384'],
  ['ECDH-ES+A128KW', 'A192CBC-HS384'],
  ['ECDH-ES+A192KW', 'A192CBC-HS384'],
  ['ECDH-ES+A256KW', 'A192CBC-HS384'],
  ['PBES2-HS256+A128KW', 'A192CBC-HS384'],
  ['PBES2-HS384+A192KW', 'A192CBC-HS384'],
  ['PBES2-HS512+A256KW', 'A192CBC-HS384'],
  ['RSA-OAEP', 'A192CBC-HS384'],
  ['RSA-OAEP-256', 'A192CBC-HS384'],
  ['RSA-OAEP-384', 'A192CBC-HS384'],
  ['RSA-OAEP-512', 'A192CBC-HS384'],
  ['RSA1_5', 'A192CBC-HS384'],
  ['dir', 'A192CBC-HS384'],
  ['A128GCMKW', 'A192GCM'],
  ['A128KW', 'A192GCM'],
  ['A192GCMKW', 'A192GCM'],
  ['A192KW', 'A192GCM'],
  ['A256GCMKW', 'A192GCM'],
  ['A256KW', 'A192GCM'],
  ['ECDH-ES', 'A192GCM'],
  ['ECDH-ES+A128KW', 'A192GCM'],
  ['ECDH-ES+A192KW', 'A192GCM'],
  ['ECDH-ES+A256KW', 'A192GCM'],
  ['PBES2-HS256+A128KW', 'A192GCM'],
  ['PBES2-HS384+A192KW', 'A192GCM'],
  ['PBES2-HS512+A256KW', 'A192GCM'],
  ['RSA-OAEP', 'A192GCM'],
  ['RSA-OAEP-256', 'A192GCM'],
  ['RSA-OAEP-384', 'A192GCM'],
  ['RSA-OAEP-512', 'A192GCM'],
  ['RSA1_5', 'A192GCM'],
  ['dir', 'A192GCM'],
  ['A128GCMKW', 'A256CBC-HS512'],
  ['A128KW', 'A256CBC-HS512'],
  ['A192GCMKW', 'A256CBC-HS512'],
  ['A192KW', 'A256CBC-HS512'],
  ['A256GCMKW', 'A256CBC-HS512'],
  ['A256KW', 'A256CBC-HS512'],
  ['ECDH-ES', 'A256CBC-HS512'],
  ['ECDH-ES+A128KW', 'A256CBC-HS512'],
  ['ECDH-ES+A192KW', 'A256CBC-HS512'],
  ['ECDH-ES+A256KW', 'A256CBC-HS512'],
  ['PBES2-HS256+A128KW', 'A256CBC-HS512'],
  ['PBES2-HS384+A192KW', 'A256CBC-HS512'],
  ['PBES2-HS512+A256KW', 'A256CBC-HS512'],
  ['RSA-OAEP', 'A256CBC-HS512'],
  ['RSA-OAEP-256', 'A256CBC-HS512'],
  ['RSA-OAEP-384', 'A256CBC-HS512'],
  ['RSA-OAEP-512', 'A256CBC-HS512'],
  ['RSA1_5', 'A256CBC-HS512'],
  ['dir', 'A256CBC-HS512'],
  ['A128GCMKW', 'A256GCM'],
  ['A128KW', 'A256GCM'],
  ['A192GCMKW', 'A256GCM'],
  ['A192KW', 'A256GCM'],
  ['A256GCMKW', 'A256GCM'],
  ['A256KW', 'A256GCM'],
  ['ECDH-ES', 'A256GCM'],
  ['ECDH-ES+A128KW', 'A256GCM'],
  ['ECDH-ES+A192KW', 'A256GCM'],
  ['ECDH-ES+A256KW', 'A256GCM'],
  ['PBES2-HS256+A128KW', 'A256GCM'],
  ['PBES2-HS384+A192KW', 'A256GCM'],
  ['PBES2-HS512+A256KW', 'A256GCM'],
  ['RSA-OAEP', 'A256GCM'],
  ['RSA-OAEP-256', 'A256GCM'],
  ['RSA-OAEP-384', 'A256GCM'],
  ['RSA-OAEP-512', 'A256GCM'],
  ['RSA1_5', 'A256GCM'],
  ['dir', 'A256GCM'],
];

describe('JSON Web Encryption Header', () => {
  const parameters: JsonWebEncryptionHeaderParameters = {
    alg: 'A128KW',
    enc: 'A128CBC-HS256',
  };

  describe('constructor', () => {
    it.each(invalidAlgs)('should throw when the provided JOSE Header Parameter "alg" is invalid.', (alg) => {
      expect(() => new JsonWebEncryptionHeader({ ...parameters, alg })).toThrowWithMessage(
        InvalidJoseHeaderError,
        'Invalid JOSE Header Parameter "alg".',
      );
    });

    it.each(invalidEncs)('should throw when the provided JOSE Header Parameter "enc" is invalid.', (enc) => {
      expect(() => new JsonWebEncryptionHeader({ ...parameters, enc })).toThrowWithMessage(
        InvalidJoseHeaderError,
        'Invalid JOSE Header Parameter "enc".',
      );
    });

    it.each(invalidZips)('should throw when the provided JOSE Header Parameter "zip" is invalid.', (zip) => {
      expect(() => new JsonWebEncryptionHeader({ ...parameters, zip })).toThrowWithMessage(
        InvalidJoseHeaderError,
        'Invalid JOSE Header Parameter "zip".',
      );
    });

    it.each(headerAlgorithms)('should return a JSON Web Encryption Header.', (alg, enc) => {
      let header!: JsonWebEncryptionHeader;

      expect(() => (header = new JsonWebEncryptionHeader({ alg, enc }))).not.toThrow();

      expect(header.keyManagementBackend).toBeInstanceOf(JsonWebEncryptionKeyManagementBackend);
      expect(header.keyManagementBackend['algorithm']).toBe(alg);

      expect(header.contentEncryptionBackend).toBeInstanceOf(JsonWebEncryptionContentEncryptionBackend);
      expect(header.contentEncryptionBackend['algorithm']).toBe(enc);

      expect(header.compressionBackend).toBeUndefined();

      expect(header.certificateChain).toBeNull();
      expect(header.jsonWebKey).toBeNull();
      expect(header.parameters).toStrictEqual({ alg, enc });
    });

    it.each(headerAlgorithms)('should return a JSON Web Encryption Header with a Compression Backend.', (alg, enc) => {
      let header!: JsonWebEncryptionHeader;

      expect(() => (header = new JsonWebEncryptionHeader({ alg, enc, zip: 'DEF' }))).not.toThrow();

      expect(header.keyManagementBackend).toBeInstanceOf(JsonWebEncryptionKeyManagementBackend);
      expect(header.keyManagementBackend['algorithm']).toBe(alg);

      expect(header.contentEncryptionBackend).toBeInstanceOf(JsonWebEncryptionContentEncryptionBackend);
      expect(header.contentEncryptionBackend['algorithm']).toBe(enc);

      expect(header.compressionBackend).toBeInstanceOf(JsonWebEncryptionCompressionBackend);
      expect(header.compressionBackend!['algorithm']).toBe<CompressionAlgorithm>('DEF');

      expect(header.certificateChain).toBeNull();
      expect(header.jsonWebKey).toBeNull();
      expect(header.parameters).toStrictEqual({ alg, enc, zip: 'DEF' });
    });
  });

  describe('isJoseHeaderParameters()', () => {
    it.each(invalidIsJoseHeaderParametersData)(
      'should return false when the provided JOSE Header Parameters is invalid.',
      (data) => {
        expect(JsonWebEncryptionHeader.isJoseHeaderParameters(data)).toBeFalse();
      },
    );

    it('should return true when the provided JOSE Header Parameters is valid.', () => {
      expect(JsonWebEncryptionHeader.isJoseHeaderParameters(parameters)).toBeTrue();
    });
  });
});
