import { Buffer } from 'buffer';

import { isNonEmptyString, jsonParse } from '@guarani/primitives';

import { InvalidJsonWebEncryptionError } from '../../../errors/invalid-jsonwebencryption.error';
import { createJsonWebEncryptionHeader } from '../../create-jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { CompactJsonWebEncryptionParameters } from './compact-jsonwebencryption.parameters';
import { CompactJsonWebEncryptionToken } from './compact-jsonwebencryption.token';

/**
 * Decodes the provided Compact JSON Web Encryption Token into its Parameters.
 *
 * @param token Compact JSON Web Encryption Token.
 * @throws {TypeError} The provided Compact JSON Web Encryption Token is invalid.
 * @throws {InvalidJsonWebEncryptionError} Failed to decode the provided Compact JSON Web Encryption Token.
 * @returns Compact JSON Web Encryption Parameters.
 */
export async function decode(token: string): Promise<CompactJsonWebEncryptionParameters> {
  if (!isNonEmptyString(token)) {
    throw new TypeError('The provided Compact JSON Web Encryption Token is invalid.');
  }

  const tokenParts = token.split('.') as CompactJsonWebEncryptionToken;

  if (tokenParts.length !== 5) {
    throw new InvalidJsonWebEncryptionError('The provided JSON Web Encryption is invalid.');
  }

  try {
    const [
      encodedProtectedHeader,
      encodedEncryptedKey,
      encodedInitializationVector,
      encodedCiphertext,
      encodedAuthenticationTag,
    ] = tokenParts;

    const protectedHeaderParameters = jsonParse(
      Buffer.from(encodedProtectedHeader, 'base64url').toString('utf8'),
    ) as JsonWebEncryptionHeaderParameters;

    const protectedHeader = await createJsonWebEncryptionHeader(protectedHeaderParameters);
    const encryptedKey = Buffer.from(encodedEncryptedKey, 'base64url');
    const initializationVector = Buffer.from(encodedInitializationVector, 'base64url');
    const ciphertext = Buffer.from(encodedCiphertext, 'base64url');
    const authenticationTag = Buffer.from(encodedAuthenticationTag, 'base64url');
    const additionalAuthenticatedData = Buffer.from(encodedProtectedHeader, 'ascii');

    const parameters: CompactJsonWebEncryptionParameters = {
      protectedHeader,
      encryptedKey,
      initializationVector,
      authenticationTag,
      additionalAuthenticatedData,
    };

    if (ciphertext.byteLength !== 0) {
      Reflect.set(parameters, 'ciphertext', ciphertext);
    }

    return parameters;
  } catch (error: unknown) {
    throw new InvalidJsonWebEncryptionError('The provided JSON Web Encryption is invalid.', { cause: error });
  }
}
