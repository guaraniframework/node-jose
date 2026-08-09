import { Buffer } from 'buffer';

import { isNonEmptyString, isPlainObject, jsonParse } from '@guarani/primitives';

import { InvalidJoseHeaderError } from '../../../errors/invalid-jose-header.error';
import { InvalidJsonWebEncryptionError } from '../../../errors/invalid-jsonwebencryption.error';
import { JoseHeader } from '../../../jose/jose-header';
import { createJsonWebEncryptionHeader } from '../../create-jsonwebencryption-header';
import { JsonWebEncryptionHeader } from '../../jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { FlattenedJsonWebEncryptionParameters } from './flattened-jsonwebencryption.parameters';
import { FlattenedJsonWebEncryptionToken } from './flattened-jsonwebencryption.token';

/**
 * Decodes the provided Flattened JSON Web Encryption Token into its Parameters.
 *
 * @param token Flattened JSON Web Encryption Token.
 * @throws {TypeError} The provided Flattened JSON Web Encryption Token is invalid.
 * @throws {InvalidJsonWebEncryptionError} Failed to decode the provided Flattened JSON Web Encryption Token.
 * @returns Flattened JSON Web Encryption Parameters.
 */
export async function decode(token: FlattenedJsonWebEncryptionToken): Promise<FlattenedJsonWebEncryptionParameters> {
  if (!isPlainObject(token)) {
    throw new TypeError('The provided Flattened JSON Web Encryption Token is invalid.');
  }

  if (!isValidFlattenedJsonWebEncryptionToken(token)) {
    throw new InvalidJsonWebEncryptionError('The provided JSON Web Encryption is invalid.');
  }

  try {
    let protectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null = null;
    let unprotectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null = null;
    let recipientUnprotectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null = null;

    if ('protected' in token) {
      protectedHeader = jsonParse(Buffer.from(token.protected, 'base64url').toString('utf8'));
    }

    if ('unprotected' in token) {
      unprotectedHeader = token.unprotected;
    }

    if ('header' in token) {
      recipientUnprotectedHeader = token.header;
    }

    const header = await getJoseHeader(protectedHeader, unprotectedHeader, recipientUnprotectedHeader);

    const parameters: FlattenedJsonWebEncryptionParameters = {
      header,
      initializationVector: Buffer.from(token.iv, 'base64url'),
      authenticationTag: Buffer.from(token.tag, 'base64url'),
    };

    if ('protected' in token) {
      Reflect.set(parameters, 'protectedHeader', protectedHeader);
    }

    if ('unprotected' in token) {
      Reflect.set(parameters, 'unprotectedHeader', unprotectedHeader);
    }

    if ('header' in token) {
      Reflect.set(parameters, 'recipientUnprotectedHeader', recipientUnprotectedHeader);
    }

    if ('encrypted_key' in token) {
      Reflect.set(parameters, 'encryptedKey', Buffer.from(token.encrypted_key, 'base64url'));
    }

    if ('aad' in token && token.aad.includes('.')) {
      Reflect.set(
        parameters,
        'additionalAuthenticatedData',
        Buffer.from(token.aad.substring(token.aad.indexOf('.') + 1), 'base64url'),
      );
    }

    if ('ciphertext' in token) {
      Reflect.set(parameters, 'ciphertext', Buffer.from(token.ciphertext, 'base64url'));
    }

    return parameters;
  } catch (error: unknown) {
    throw new InvalidJsonWebEncryptionError('The provided JSON Web Encryption is invalid.', { cause: error });
  }
}

// #region Helper Methods.
function isValidFlattenedJsonWebEncryptionToken(token: FlattenedJsonWebEncryptionToken): boolean {
  if (!('protected' in token) && !('unprotected' in token) && !('header' in token)) {
    return false;
  }

  if (
    'protected' in token &&
    (!isNonEmptyString(token.protected) ||
      !JoseHeader.isJoseHeaderParameters(jsonParse(Buffer.from(token.protected, 'base64url').toString('utf8'))))
  ) {
    return false;
  }

  if ('unprotected' in token && !JoseHeader.isJoseHeaderParameters(token.unprotected)) {
    return false;
  }

  if ('header' in token && !JoseHeader.isJoseHeaderParameters(token.header)) {
    return false;
  }

  if ('encrypted_key' in token && !isNonEmptyString(token.encrypted_key)) {
    return false;
  }

  if ('aad' in token && !isNonEmptyString(token.aad)) {
    return false;
  }

  if (!isNonEmptyString(token.iv)) {
    return false;
  }

  if ('ciphertext' in token && !isNonEmptyString(token.ciphertext)) {
    return false;
  }

  if (!isNonEmptyString(token.tag)) {
    return false;
  }

  return true;
}

async function getJoseHeader(
  protectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null,
  unprotectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null,
  recipientUnprotectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null,
): Promise<JsonWebEncryptionHeader> {
  const headerKeys = [
    ...Object.keys(protectedHeader ?? {}),
    ...Object.keys(unprotectedHeader ?? {}),
    ...Object.keys(recipientUnprotectedHeader ?? {}),
  ];

  if (headerKeys.length !== new Set(headerKeys).size) {
    throw new InvalidJoseHeaderError('Cannot have repeated JSON Web Encryption Header Parameters.');
  }

  const headerParameters = {
    ...(protectedHeader ?? {}),
    ...(unprotectedHeader ?? {}),
    ...(recipientUnprotectedHeader ?? {}),
  } as JsonWebEncryptionHeaderParameters;

  return await createJsonWebEncryptionHeader(headerParameters);
}
// #endregion
