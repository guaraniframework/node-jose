import { Buffer } from 'buffer';

import { InvalidJsonWebEncryptionError } from '../../../errors/invalid-jsonwebencryption.error';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebEncryptionHeader } from '../../jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { CompactJsonWebEncryption } from './compact-jsonwebencryption';
import { deserialize } from './deserialize';

const invalidDeserializeOptions: any[] = [
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

const invalidExpectedAlgorithms: any[] = [
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
  ['a'],
];

const invalidDetachedCiphertexts: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  Symbol('a'),
  Buffer,
  () => 1,
  {},
  [],
  Buffer.alloc(0),
];

const invalidTokens: any[] = [
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

describe('deserialize()', () => {
  const wrongEncryptedKeyToken =
    'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.' +
    'anBl9PSuJobKWwzWzJCqfMnejCvM5-WadN3zXMGyoCLW8_xmUldY3Q.' +
    'AxY8DCtDaGlsbGljb3RoZQ.' +
    'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.' +
    'U0m_YmjN04DJvceFICbCVQ';

  const wrongInitializationVectorToken =
    'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.' +
    '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.' +
    'eE63cGwX4T7eSspUA72t2Q.' +
    'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.' +
    'U0m_YmjN04DJvceFICbCVQ';

  const wrongCiphertextToken =
    'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.' +
    '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.' +
    'AxY8DCtDaGlsbGljb3RoZQ.' +
    'giYkZlt454236QV7AdREOuT0UOQrnNW1dpTna5JQpDk.' +
    'U0m_YmjN04DJvceFICbCVQ';

  const wrongAuthenticationTagToken =
    'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.' +
    '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.' +
    'AxY8DCtDaGlsbGljb3RoZQ.' +
    'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.' +
    '24tpOFXtrTHSIdllxDRtlw';

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

  const ciphertext = Buffer.from('KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY', 'base64url');
  const compressedCiphertext = Buffer.from('7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA', 'base64url');

  const jsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'GawgguFyGrWKav7AX4VKUg' });

  it.each(invalidDeserializeOptions)('should throw when the provided options is invalid.', async (options) => {
    await expect(deserialize(attachedToken, options)).rejects.toThrowWithMessage(
      TypeError,
      'The provided options is invalid.',
    );
  });

  it.each(invalidJsonWebKeys)('should throw when the provided option "jsonWebKey" is invalid.', async (jsonWebKey) => {
    await expect(deserialize(attachedToken, { jsonWebKey })).rejects.toThrowWithMessage(
      TypeError,
      'The provided option "jsonWebKey" is invalid.',
    );
  });

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided option "expectedKeyManagementAlgorithms" is invalid.',
    async (expectedKeyManagementAlgorithms) => {
      await expect(deserialize(attachedToken, { expectedKeyManagementAlgorithms })).rejects.toThrowWithMessage(
        TypeError,
        'The provided option "expectedKeyManagementAlgorithms" is invalid.',
      );
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided option "expectedContentEncryptionAlgorithms" is invalid.',
    async (expectedContentEncryptionAlgorithms) => {
      await expect(deserialize(attachedToken, { expectedContentEncryptionAlgorithms })).rejects.toThrowWithMessage(
        TypeError,
        'The provided option "expectedContentEncryptionAlgorithms" is invalid.',
      );
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided option "expectedCompressionAlgorithms" is invalid.',
    async (expectedCompressionAlgorithms) => {
      await expect(deserialize(attachedToken, { expectedCompressionAlgorithms })).rejects.toThrowWithMessage(
        TypeError,
        'The provided option "expectedCompressionAlgorithms" is invalid.',
      );
    },
  );

  it.each(invalidDetachedCiphertexts)(
    'should throw when the provided option "detachedCiphertext" is invalid.',
    async (detachedCiphertext) => {
      await expect(deserialize(detachedToken, { detachedCiphertext })).rejects.toThrowWithMessage(
        TypeError,
        'The provided option "detachedCiphertext" is invalid.',
      );
    },
  );

  it.each(invalidTokens)(
    'should throw when the provided Compact JSON Web Encryption Token is invalid.',
    async (token) => {
      await expect(deserialize(token)).rejects.toThrowWithMessage(
        TypeError,
        'The provided Compact JSON Web Encryption Token is invalid.',
      );
    },
  );

  it('should throw when deserializing a Detached Compact JSON Web Encryption Token and not providing a Detached Ciphertext.', async () => {
    await expect(deserialize(detachedToken)).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'The JSON Web Encryption requires a valid Ciphertext.',
    );
  });

  it('should throw when providing a Detached Ciphertext for a Compact JSON Web Encryption Token that already has a Ciphertext.', async () => {
    await expect(deserialize(attachedToken, { detachedCiphertext: ciphertext })).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'The provided JSON Web Encryption already has a defined Ciphertext.',
    );
  });

  it('should throw when the JSON Web Encryption Key Management Algorithm of the Compact JSON Web Encryption Token is unexpected.', async () => {
    await expect(
      deserialize(attachedToken, { expectedKeyManagementAlgorithms: ['A256KW'] }),
    ).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'Unexpected JSON Web Encryption Key Management Algorithm "A128KW".',
    );
  });

  it('should throw when the JSON Web Encryption Content Encryption Algorithm of the Compact JSON Web Encryption Token is unexpected.', async () => {
    await expect(
      deserialize(attachedToken, { expectedContentEncryptionAlgorithms: ['A256CBC-HS512'] }),
    ).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'Unexpected JSON Web Encryption Content Encryption Algorithm "A128CBC-HS256".',
    );
  });

  it('should throw when the JSON Web Encryption Compression Algorithm of the Compact JSON Web Encryption Token is unexpected.', async () => {
    await expect(deserialize(attachedToken, { expectedCompressionAlgorithms: ['DEF'] })).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'Unexpected JSON Web Encryption Compression Algorithm "".',
    );
  });

  it('should throw when the provided Encrypted Key fails to deserialize the provided Compact JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongEncryptedKeyToken, { jsonWebKey })).rejects.toThrow();
  });

  it('should throw when the provided Initialization Vector fails to deserialize the provided Compact JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongInitializationVectorToken, { jsonWebKey })).rejects.toThrow();
  });

  it('should throw when the provided Ciphertext fails to deserialize the provided Compact JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongCiphertextToken, { jsonWebKey })).rejects.toThrow();
  });

  it('should throw when the provided Authentication Tag fails to deserialize the provided Compact JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongAuthenticationTagToken, { jsonWebKey })).rejects.toThrow();
  });

  it('should return the deserialized Compact JSON Web Encryption from an Attached Compact JSON Web Encryption Token.', async () => {
    let jwe!: CompactJsonWebEncryption;

    await expect(async () => (jwe = await deserialize(attachedToken, { jsonWebKey }))).resolves.not.toThrow();

    expect(jwe.protectedHeader).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.protectedHeader.parameters).toStrictEqual(protectedHeader);
    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Compact JSON Web Encryption from a Detached Compact JSON Web Encryption Token.', async () => {
    let jwe!: CompactJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(detachedToken, { jsonWebKey, detachedCiphertext: ciphertext })),
    ).resolves.not.toThrow();

    expect(jwe.protectedHeader).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.protectedHeader.parameters).toStrictEqual(protectedHeader);
    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Compact JSON Web Encryption from a Compressed Attached Compact JSON Web Encryption Token.', async () => {
    let jwe!: CompactJsonWebEncryption;

    await expect(async () => (jwe = await deserialize(compressedAttachedToken, { jsonWebKey }))).resolves.not.toThrow();

    expect(jwe.protectedHeader).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.protectedHeader.parameters).toStrictEqual(protectedCompressedHeader);
    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Compact JSON Web Encryption from a Compressed Detached Compact JSON Web Encryption Token.', async () => {
    let jwe!: CompactJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedDetachedToken, { jsonWebKey, detachedCiphertext: compressedCiphertext });
    }).resolves.not.toThrow();

    expect(jwe.protectedHeader).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.protectedHeader.parameters).toStrictEqual(protectedCompressedHeader);
    expect(jwe.plaintext).toStrictEqual(plaintext);
  });
});
