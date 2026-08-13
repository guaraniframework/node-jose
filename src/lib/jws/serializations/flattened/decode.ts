import { Buffer } from 'buffer';

import { isNonEmptyString, isPlainObject, jsonParse } from '@guarani/primitives';

import { InvalidJoseHeaderError } from '../../../errors/invalid-jose-header.error';
import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { JoseHeader } from '../../../jose/jose-header';
import { createJsonWebSignatureHeader } from '../../create-jsonwebsignature-header';
import { JsonWebSignatureHeader } from '../../jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { FlattenedJsonWebSignatureParameters } from './flattened-jsonwebsignature.parameters';
import { FlattenedJsonWebSignatureToken } from './flattened-jsonwebsignature.token';

/**
 * Decodes the provided Flattened JSON Web Signature Token into its Parameters.
 *
 * @param token Flattened JSON Web Signature Token.
 * @throws {TypeError} The provided Flattened JSON Web Signature Token is invalid.
 * @throws {InvalidJsonWebSignatureError} Failed to decode the provided Flattened JSON Web Signature Token.
 * @returns Flattened JSON Web Signature Parameters.
 */
export async function decode(token: FlattenedJsonWebSignatureToken): Promise<FlattenedJsonWebSignatureParameters> {
  if (!isPlainObject(token)) {
    throw new TypeError('The provided Flattened JSON Web Signature Token is invalid.');
  }

  if (!isValidFlattenedJsonWebSignatureToken(token)) {
    throw new InvalidJsonWebSignatureError('The provided JSON Web Signature is invalid.');
  }

  try {
    let protectedHeader: Partial<JsonWebSignatureHeaderParameters> | null = null;
    let unprotectedHeader: Partial<JsonWebSignatureHeaderParameters> | null = null;

    if ('protected' in token) {
      protectedHeader = jsonParse(Buffer.from(token.protected, 'base64url').toString('utf8'));
    }

    if ('header' in token) {
      unprotectedHeader = token.header;
    }

    const header = await getJoseHeader(protectedHeader, unprotectedHeader);
    const signature = Buffer.from(token.signature, 'base64url');

    const parameters: FlattenedJsonWebSignatureParameters = { header, signature };

    if ('protected' in token) {
      Reflect.set(parameters, 'protectedHeader', protectedHeader);
    }

    if ('header' in token) {
      Reflect.set(parameters, 'unprotectedHeader', unprotectedHeader);
    }

    if ('payload' in token) {
      Reflect.set(
        parameters,
        'payload',
        Buffer.from(token.payload, header.parameters.b64 === false ? 'utf8' : 'base64url'),
      );
    }

    return parameters;
  } catch (error: unknown) {
    throw new InvalidJsonWebSignatureError('The provided JSON Web Signature is invalid.', { cause: error });
  }
}

// #region Helper Methods
function isValidFlattenedJsonWebSignatureToken(token: FlattenedJsonWebSignatureToken): boolean {
  if (!('protected' in token) && !('header' in token)) {
    return false;
  }

  if (
    'protected' in token &&
    (!isNonEmptyString(token.protected) ||
      !JoseHeader.isJoseHeaderParameters(jsonParse(Buffer.from(token.protected, 'base64url').toString('utf8'))))
  ) {
    return false;
  }

  if ('header' in token && !JoseHeader.isJoseHeaderParameters(token.header)) {
    return false;
  }

  if ('payload' in token && !isNonEmptyString(token.payload)) {
    return false;
  }

  if (!isNonEmptyString(token.signature)) {
    return false;
  }

  return true;
}

async function getJoseHeader(
  protectedHeader: Partial<JsonWebSignatureHeaderParameters> | null,
  unprotectedHeader: Partial<JsonWebSignatureHeaderParameters> | null,
): Promise<JsonWebSignatureHeader> {
  if (!new Set(Object.keys(protectedHeader ?? {})).isDisjointFrom(new Set(Object.keys(unprotectedHeader ?? {})))) {
    throw new InvalidJoseHeaderError('Cannot have repeated JSON Web Signature Header Parameters.');
  }

  if (unprotectedHeader !== null) {
    if ('crit' in unprotectedHeader) {
      throw new InvalidJoseHeaderError('Invalid Unprotected JOSE Header Parameter "crit".');
    }

    if ('b64' in unprotectedHeader) {
      throw new InvalidJoseHeaderError('Invalid Unprotected JOSE Header Parameter "b64".');
    }
  }

  const headerParameters = {
    ...(protectedHeader ?? {}),
    ...(unprotectedHeader ?? {}),
  } as JsonWebSignatureHeaderParameters;

  return await createJsonWebSignatureHeader(headerParameters);
}
// #endregion
