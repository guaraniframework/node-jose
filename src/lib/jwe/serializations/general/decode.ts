import { Buffer } from 'buffer';

import { isNonEmptyString, isPlainObject, jsonParse } from '@guarani/primitives';

import { InvalidJoseHeaderError } from '../../../errors/invalid-jose-header.error';
import { InvalidJsonWebEncryptionError } from '../../../errors/invalid-jsonwebencryption.error';
import { JoseHeader } from '../../../jose/jose-header';
import { createJsonWebEncryptionHeader } from '../../create-jsonwebencryption-header';
import { JsonWebEncryptionHeader } from '../../jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { GeneralJsonWebEncryptionParameters } from './general-jsonwebencryption.parameters';
import { GeneralJsonWebEncryptionToken } from './general-jsonwebencryption.token';
import { GeneralJsonWebEncryptionParametersRecipient } from './general-jsonwebencryption-parameters-recipient';

/**
 * Decodes the provided General JSON Web Encryption Token into its Parameters.
 *
 * @param token General JSON Web Encryption Token.
 * @throws {TypeError} The provided General JSON Web Encryption Token is invalid.
 * @throws {InvalidJsonWebEncryptionError} Failed to decode the provided General JSON Web Encryption Token.
 * @returns General JSON Web Encryption Parameters.
 */
export async function decode(token: GeneralJsonWebEncryptionToken): Promise<GeneralJsonWebEncryptionParameters> {
  if (!isPlainObject(token)) {
    throw new TypeError('The provided General JSON Web Encryption Token is invalid.');
  }

  if (!isValidGeneralJsonWebEncryptionToken(token)) {
    throw new InvalidJsonWebEncryptionError('The provided JSON Web Encryption is invalid.');
  }

  try {
    let protectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null = null;

    if ('protected' in token) {
      protectedHeader = jsonParse(Buffer.from(token.protected, 'base64url').toString('utf8'));
    }

    const recipients = await Promise.all(
      token.recipients.map<Promise<GeneralJsonWebEncryptionParametersRecipient>>(async (tokenRecipient) => {
        const recipient: GeneralJsonWebEncryptionParametersRecipient = {
          header: await getJoseHeader(protectedHeader, token.unprotected, tokenRecipient.header),
          encryptedKey: Buffer.from(tokenRecipient.encrypted_key, 'base64url'),
        };

        if ('header' in tokenRecipient) {
          Reflect.set(recipient, 'recipientUnprotectedHeader', tokenRecipient.header);
        }

        return recipient;
      }),
    );

    const parameters: GeneralJsonWebEncryptionParameters = {
      initializationVector: Buffer.from(token.iv, 'base64url'),
      authenticationTag: Buffer.from(token.tag, 'base64url'),
      recipients,
    };

    if (protectedHeader !== null) {
      Reflect.set(parameters, 'protectedHeader', protectedHeader);
    }

    if ('unprotected' in token) {
      Reflect.set(parameters, 'unprotectedHeader', token.unprotected);
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

// #region Helper Methods
function isValidGeneralJsonWebEncryptionToken(token: GeneralJsonWebEncryptionToken): boolean {
  if (!isNonEmptyString(token.iv)) {
    return false;
  }

  if ('aad' in token && !isNonEmptyString(token.aad)) {
    return false;
  }

  if ('ciphertext' in token && !isNonEmptyString(token.ciphertext)) {
    return false;
  }

  if (!isNonEmptyString(token.tag)) {
    return false;
  }

  if ('protected' in token && !isNonEmptyString(token.protected)) {
    return false;
  }

  if ('unprotected' in token && !JoseHeader.isJoseHeaderParameters(token.unprotected)) {
    return false;
  }

  if (
    !Array.isArray(token.recipients) ||
    token.recipients.length === 0 ||
    token.recipients.some((recipient) => !isPlainObject(recipient))
  ) {
    return false;
  }

  for (const recipient of token.recipients) {
    if (!('protected' in token) && !('unprotected' in token) && !('header' in recipient)) {
      return false;
    }

    if ('header' in recipient && !JoseHeader.isJoseHeaderParameters(recipient.header)) {
      return false;
    }

    if (!isNonEmptyString(recipient.encrypted_key)) {
      return false;
    }
  }

  return true;
}

async function getJoseHeader(
  protectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null | undefined,
  unprotectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null | undefined,
  recipientUnprotectedHeader: Partial<JsonWebEncryptionHeaderParameters> | null | undefined,
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
