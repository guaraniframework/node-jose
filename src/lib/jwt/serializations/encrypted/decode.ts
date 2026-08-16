import { isNonEmptyString } from '@guarani/primitives';

import { InvalidJsonWebTokenError } from '../../../errors/invalid-jsonwebtoken.error';
import { jwe } from '../../../jwe/serializations';
import { EncryptedJsonWebTokenParameters } from './encrypted-jsonwebtoken.parameters';

/**
 * Decodes the provided Encrypted JSON Web Token into its Parameters.
 *
 * @param token Encrypted JSON Web Token.
 * @throws {TypeError} The provided Encrypted JSON Web Token is invalid.
 * @throws {InvalidJsonWebTokenError} Failed to decode the provided Encrypted JSON Web Token.
 * @returns Encrypted JSON Web Token Parameters.
 */
export async function decode(token: string): Promise<EncryptedJsonWebTokenParameters> {
  if (!isNonEmptyString(token)) {
    throw new TypeError('The provided Encrypted JSON Web Token is invalid.');
  }

  try {
    const {
      additionalAuthenticatedData,
      authenticationTag,
      ciphertext,
      encryptedKey,
      initializationVector,
      protectedHeader,
    } = await jwe.compact.decode(token);

    if (!Buffer.isBuffer(ciphertext)) {
      throw new InvalidJsonWebTokenError('The provided JSON Web Token is invalid.');
    }

    return {
      additionalAuthenticatedData,
      authenticationTag,
      ciphertext,
      encryptedKey,
      header: protectedHeader,
      initializationVector,
    };
  } catch (error: unknown) {
    throw new InvalidJsonWebTokenError('The provided JSON Web Token is invalid.', { cause: error });
  }
}
