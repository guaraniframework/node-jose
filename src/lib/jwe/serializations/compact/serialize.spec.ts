import { Buffer } from 'buffer';

import { AESKWJsonWebEncryptionKeyManagementBackend } from '../../../jwa/jwe/alg/aeskw/aeskw-jsonwebencryption-key-management.backend';
import { AESCBCJsonWebEncryptionContentEncryptionBackend } from '../../../jwa/jwe/enc/aescbc/aescbc-jsonwebencryption-content-encryption.backend';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { serialize } from './serialize';

const invalidPlaintexts: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  'a',
  Symbol('a'),
  Buffer,
  () => 1,
  {},
  [],
  Buffer.alloc(0),
];

const invalidProtectedHeaders: any[] = [
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
];

const invalidSerializeOptions: any[] = [null, true, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, []];

const invalidJsonWebKeys: any[] = [
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
];

const invalidDetacheds: any[] = [
  undefined,
  null,
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
];

describe('serialize()', () => {
  const attachedToken =
    'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.' +
    '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.' +
    'AxY8DCtDaGlsbGljb3RoZQ.' +
    'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.' +
    'U0m_YmjN04DJvceFICbCVQ';

  const detachedToken =
    'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.' +
    '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.' +
    'AxY8DCtDaGlsbGljb3RoZQ.' +
    '.' +
    'U0m_YmjN04DJvceFICbCVQ';

  const compressedAttachedToken =
    'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIn0.' +
    '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.' +
    'AxY8DCtDaGlsbGljb3RoZQ.' +
    '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA.' +
    'PGfg9jnB_-hnQBGbNu8jBQ';

  const compressedDetachedToken =
    'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIn0.' +
    '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.' +
    'AxY8DCtDaGlsbGljb3RoZQ.' +
    '.' +
    'PGfg9jnB_-hnQBGbNu8jBQ';

  const plaintext = Buffer.from('Live long and prosper.');
  const protectedHeader: JsonWebEncryptionHeaderParameters = { alg: 'A128KW', enc: 'A128CBC-HS256' };
  const protectedCompressedHeader: JsonWebEncryptionHeaderParameters = {
    alg: 'A128KW',
    enc: 'A128CBC-HS256',
    zip: 'DEF',
  };

  const contentEncryptionKey = Buffer.from('BNMfxVSd_P4LZJ36P6pqzmt81C1vawnbyLEA8I-cLM8', 'base64url');
  const initializationVector = Buffer.from('AxY8DCtDaGlsbGljb3RoZQ', 'base64url');

  const jsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'GawgguFyGrWKav7AX4VKUg' });

  beforeEach(() => {
    jest
      .spyOn(AESKWJsonWebEncryptionKeyManagementBackend.prototype, 'generateContentEncryptionKey')
      .mockResolvedValueOnce(contentEncryptionKey);

    jest
      .spyOn(AESCBCJsonWebEncryptionContentEncryptionBackend.prototype, 'generateInitializationVector')
      .mockResolvedValueOnce(initializationVector);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it.each(invalidPlaintexts)('should throw when the provided Plaintext is invalid.', async (plaintext) => {
    await expect(serialize(plaintext, protectedHeader)).rejects.toThrowWithMessage(
      TypeError,
      'The provided Plaintext is invalid.',
    );
  });

  it.each(invalidProtectedHeaders)(
    'should throw when the provided JSON Web Encryption Protected Header is invalid.',
    async (protectedHeader) => {
      await expect(serialize(plaintext, protectedHeader)).rejects.toThrowWithMessage(
        TypeError,
        'The provided JSON Web Encryption Protected Header is invalid.',
      );
    },
  );

  it.each(invalidSerializeOptions)('should throw when the provided options is invalid.', async (options) => {
    await expect(serialize(plaintext, protectedHeader, options)).rejects.toThrowWithMessage(
      TypeError,
      'The provided options is invalid.',
    );
  });

  it.each(invalidJsonWebKeys)('should throw when the provided option "jsonWebKey" is invalid.', async (jsonWebKey) => {
    await expect(serialize(plaintext, protectedHeader, { jsonWebKey })).rejects.toThrowWithMessage(
      TypeError,
      'The provided option "jsonWebKey" is invalid.',
    );
  });

  it.each(invalidDetacheds)('should throw when the provided option "detached" is invalid.', async (detached) => {
    await expect(serialize(plaintext, protectedHeader, { detached })).rejects.toThrowWithMessage(
      TypeError,
      'The provided option "detached" is invalid.',
    );
  });

  it('should throw when failing to serialize the provided Compact JSON Web Encryption.', async () => {
    await expect(serialize(plaintext, protectedHeader)).rejects.toThrow();
  });

  it('should serialize a Compact JSON Web Encryption Attached Token.', async () => {
    await expect(serialize(plaintext, protectedHeader, { jsonWebKey })).resolves.toStrictEqual(attachedToken);
  });

  it('should serialize a Compact JSON Web Encryption Detached Token.', async () => {
    await expect(serialize(plaintext, protectedHeader, { jsonWebKey, detached: true })).resolves.toStrictEqual(
      detachedToken,
    );
  });

  it('should serialize a Compact JSON Web Encryption Compressed Attached Token.', async () => {
    await expect(serialize(plaintext, protectedCompressedHeader, { jsonWebKey })).resolves.toStrictEqual(
      compressedAttachedToken,
    );
  });

  it('should serialize a Compact JSON Web Encryption Compressed Detached Token.', async () => {
    await expect(
      serialize(plaintext, protectedCompressedHeader, { jsonWebKey, detached: true }),
    ).resolves.toStrictEqual(compressedDetachedToken);
  });
});
