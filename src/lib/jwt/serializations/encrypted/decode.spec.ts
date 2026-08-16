import { Buffer } from 'buffer';

import { InvalidJsonWebTokenError } from '../../../errors/invalid-jsonwebtoken.error';
import { JsonWebEncryptionHeader } from '../../../jwe/jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../../jwe/jsonwebencryption-header.parameters';
import { decode } from './decode';
import { EncryptedJsonWebTokenParameters } from './encrypted-jsonwebtoken.parameters';

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
  const missingCiphertextToken =
    'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.' +
    '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.' +
    'AxY8DCtDaGlsbGljb3RoZQ.' +
    '.' +
    'FYJuxuNgWc45ek7eLeNJNQ';

  const token =
    'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.' +
    '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.' +
    'AxY8DCtDaGlsbGljb3RoZQ.' +
    'FgA-dGeGpV_KbHo21rm9iyadtKRGK3ltsG-qzALFjmqapZ9g0pcLo3VGGoGr6SM1' +
    'lRkKHp9aSLswiWYjSsSYV8OETrMDyw3zDZTQuGvSQzTfmqeEymto5Np5H8tAEOfX' +
    'CnMddBwg0QEWpMu9s6FcNy_rsTuJDbce1J2FpaIDRADHEui7rIrISlLDIu0tAOOF' +
    'wJtztt00tEyhjce9QE9qMn0pSI8_4z8CbXFVM1rJih4WuNso3qlmlsQLg_So3icA' +
    '6QpxXJ0pJhjEkS6pJhRRJw.' +
    'FYJuxuNgWc45ek7eLeNJNQ';

  const header: JsonWebEncryptionHeaderParameters = { alg: 'A128KW', enc: 'A128CBC-HS256' };

  const encryptedKey = Buffer.from('6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ', 'base64url');
  const initializationVector = Buffer.from('AxY8DCtDaGlsbGljb3RoZQ', 'base64url');

  const ciphertext = Buffer.from(
    'FgA-dGeGpV_KbHo21rm9iyadtKRGK3ltsG-qzALFjmqapZ9g0pcLo3VGGoGr6SM1' +
      'lRkKHp9aSLswiWYjSsSYV8OETrMDyw3zDZTQuGvSQzTfmqeEymto5Np5H8tAEOfX' +
      'CnMddBwg0QEWpMu9s6FcNy_rsTuJDbce1J2FpaIDRADHEui7rIrISlLDIu0tAOOF' +
      'wJtztt00tEyhjce9QE9qMn0pSI8_4z8CbXFVM1rJih4WuNso3qlmlsQLg_So3icA' +
      '6QpxXJ0pJhjEkS6pJhRRJw',
    'base64url',
  );

  const authenticationTag = Buffer.from('FYJuxuNgWc45ek7eLeNJNQ', 'base64url');
  const additionalAuthenticatedData = Buffer.from('eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', 'ascii');

  it.each(invalidTokens)('should throw when the provided Encrypted JSON Web Token is invalid.', async (token) => {
    await expect(decode(token)).rejects.toThrowWithMessage(
      TypeError,
      'The provided Encrypted JSON Web Token is invalid.',
    );
  });

  it.each(invalidTokenFormats)(
    'should throw when the provided Encrypted JSON Web Token has an invalid format.',
    async (token) => {
      await expect(decode(token)).rejects.toThrowWithMessage(
        InvalidJsonWebTokenError,
        'The provided JSON Web Token is invalid.',
      );
    },
  );

  it('should throw when the provided Encrypted JSON Web Token is missing a Ciphertext.', async () => {
    await expect(decode(missingCiphertextToken)).rejects.toThrowWithMessage(
      InvalidJsonWebTokenError,
      'The provided JSON Web Token is invalid.',
    );
  });

  it('should return the Encrypted JSON Web Token Parameters from the provided Encrypted JSON Web Token.', async () => {
    await expect(decode(token)).resolves.toStrictEqual<EncryptedJsonWebTokenParameters>({
      additionalAuthenticatedData,
      authenticationTag,
      ciphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(header),
      initializationVector,
    });
  });
});
