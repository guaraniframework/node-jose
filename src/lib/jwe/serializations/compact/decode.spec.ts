import { Buffer } from 'buffer';

import { InvalidJsonWebEncryptionError } from '../../../errors/invalid-jsonwebencryption.error';
import { JsonWebEncryptionHeader } from '../../jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { CompactJsonWebEncryptionParameters } from './compact-jsonwebencryption.parameters';
import { decode } from './decode';

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

const invalidTokenFormats = ['a', '.a', '.a.b.c.d', 'a.b', 'a.b.c.d.e.f'];

describe('decode()', () => {
  const headerlessToken =
    '.' +
    '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.' +
    'AxY8DCtDaGlsbGljb3RoZQ.' +
    'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.' +
    'U0m_YmjN04DJvceFICbCVQ';

  const invalidHeaderToken =
    'e30.' +
    '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.' +
    'AxY8DCtDaGlsbGljb3RoZQ.' +
    'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.' +
    'U0m_YmjN04DJvceFICbCVQ';

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

  const protectedHeader: JsonWebEncryptionHeaderParameters = { alg: 'A128KW', enc: 'A128CBC-HS256' };

  const encryptedKey = Buffer.from('6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ', 'base64url');
  const initializationVector = Buffer.from('AxY8DCtDaGlsbGljb3RoZQ', 'base64url');
  const ciphertext = Buffer.from('KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY', 'base64url');
  const authenticationTag = Buffer.from('U0m_YmjN04DJvceFICbCVQ', 'base64url');
  const additionalAuthenticatedData = Buffer.from('eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', 'ascii');

  it.each(invalidTokens)(
    'should throw when the provided Compact JSON Web Encryption Token is invalid.',
    async (token) => {
      await expect(decode(token)).rejects.toThrowWithMessage(
        TypeError,
        'The provided Compact JSON Web Encryption Token is invalid.',
      );
    },
  );

  it.each(invalidTokenFormats)(
    'should throw when the provided Compact JSON Web Encryption Token has an invalid format.',
    async (token) => {
      await expect(decode(token)).rejects.toThrowWithMessage(
        InvalidJsonWebEncryptionError,
        'The provided JSON Web Encryption is invalid.',
      );
    },
  );

  it('should throw when failing to parse the Protected Header of the provided Compact JSON Web Encryption Token.', async () => {
    await expect(decode(headerlessToken)).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'The provided JSON Web Encryption is invalid.',
    );
  });

  it('should throw when the Protected Header of the provided Compact JSON Web Encryption Token is invalid.', async () => {
    await expect(decode(invalidHeaderToken)).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'The provided JSON Web Encryption is invalid.',
    );
  });

  it('should return the Compact JSON Web Encryption Parameters from an Attached Compact JSON Web Encryption Token.', async () => {
    await expect(decode(attachedToken)).resolves.toStrictEqual<CompactJsonWebEncryptionParameters>({
      protectedHeader: new JsonWebEncryptionHeader(protectedHeader),
      encryptedKey,
      initializationVector,
      ciphertext,
      authenticationTag,
      additionalAuthenticatedData,
    });
  });

  it('should return the Compact JSON Web Encryption Parameters from a Detached Compact JSON Web Encryption Token.', async () => {
    await expect(decode(detachedToken)).resolves.toStrictEqual<CompactJsonWebEncryptionParameters>({
      protectedHeader: new JsonWebEncryptionHeader(protectedHeader),
      encryptedKey,
      initializationVector,
      authenticationTag,
      additionalAuthenticatedData,
    });
  });
});
