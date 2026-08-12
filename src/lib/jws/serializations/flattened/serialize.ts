import { Buffer } from 'buffer';

import { isPlainObject, jsonStringify } from '@guarani/primitives';

import { InvalidJoseHeaderError } from '../../../errors/invalid-jose-header.error';
import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { JoseHeader } from '../../../jose/jose-header';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { createJsonWebSignatureHeader } from '../../create-jsonwebsignature-header';
import { JsonWebSignatureHeader } from '../../jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { FlattenedJsonWebSignatureHeaders } from './flattened-jsonwebsignature.headers';
import { FlattenedJsonWebSignatureToken } from './flattened-jsonwebsignature.token';
import { FlattenedJsonWebSignatureSerializationOptions } from './flattened-jsonwebsignature-serialization.options';

/**
 * Serializes the provided JSON Web Signature Parameters into a Flattened Token.
 *
 * @param payload JSON Web Signature Payload.
 * @param headers JSON Web Signature Headers Parameters.
 * @param options Flattened JSON Web Signature serialization options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @throws {InvalidJoseHeaderError} One of the provided JSON Web Signature Header Parameters is invalid.
 * @throws {InvalidJsonWebSignatureError} Failed to serialize the Flattened JSON Web Signature.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Flattened JSON Web Signature.
 * @returns Flattened JSON Web Signature Token.
 */
export async function serialize(
  payload: Buffer,
  headers: FlattenedJsonWebSignatureHeaders,
  options: FlattenedJsonWebSignatureSerializationOptions = {},
): Promise<FlattenedJsonWebSignatureToken> {
  validatePayload(payload);
  const header = await validateHeaders(headers);
  validateOptions(options);

  const { detached, jwk } = options;
  const { digitalSignatureBackend, parameters } = header;

  const jsonWebKey = jwk ?? header.jsonWebKey!;

  if (parameters.b64 === false && payload.includes(0x2e) && detached !== true) {
    throw new InvalidJsonWebSignatureError('The provided Unencoded Payload cannot be serialized.');
  }

  const encodedProtectedHeader =
    'protectedHeader' in headers
      ? Buffer.from(jsonStringify(headers.protectedHeader), 'utf8').toString('base64url')
      : '';

  const encodedPayload = payload.toString(parameters.b64 === false ? 'utf8' : 'base64url');

  const message =
    parameters.b64 === false
      ? Buffer.concat([Buffer.from(`${encodedProtectedHeader}.`, 'ascii'), payload])
      : Buffer.from(`${encodedProtectedHeader}.${encodedPayload}`, 'ascii');

  const signature = await digitalSignatureBackend.sign(message, jsonWebKey);

  const token: FlattenedJsonWebSignatureToken = { signature: signature.toString('base64url') };

  if ('unprotectedHeader' in headers) {
    Reflect.set(token, 'header', headers.unprotectedHeader);
  }

  if ('protectedHeader' in headers) {
    Reflect.set(token, 'protected', encodedProtectedHeader);
  }

  if (detached !== true) {
    Reflect.set(token, 'payload', encodedPayload);
  }

  return token;
}

// #region Helper Methods.
function validatePayload(payload: Buffer): void {
  if (!Buffer.isBuffer(payload) || payload.byteLength === 0) {
    throw new TypeError('The provided Payload is invalid.');
  }
}

async function validateHeaders(headers: FlattenedJsonWebSignatureHeaders): Promise<JsonWebSignatureHeader> {
  if (!isPlainObject(headers)) {
    throw new TypeError('The provided JSON Web Signature Headers is invalid.');
  }

  if ('protectedHeader' in headers && !JoseHeader.isJoseHeaderParameters(headers.protectedHeader)) {
    throw new TypeError('The provided JSON Web Signature Protected Header is invalid.');
  }

  if ('unprotectedHeader' in headers && !JoseHeader.isJoseHeaderParameters(headers.unprotectedHeader)) {
    throw new TypeError('The provided JSON Web Signature Unprotected Header is invalid.');
  }

  if (!('protectedHeader' in headers) && !('unprotectedHeader' in headers)) {
    throw new InvalidJoseHeaderError('Missing at least one required JSON Web Signature Header.');
  }

  if (
    !new Set(Object.keys(headers.protectedHeader ?? {})).isDisjointFrom(
      new Set(Object.keys(headers.unprotectedHeader ?? {})),
    )
  ) {
    throw new InvalidJoseHeaderError('Cannot have repeated JSON Web Signature Header Parameters.');
  }

  if ('unprotectedHeader' in headers) {
    if ('crit' in headers.unprotectedHeader) {
      throw new InvalidJoseHeaderError('Invalid Unprotected JOSE Header Parameter "crit".');
    }

    if ('b64' in headers.unprotectedHeader) {
      throw new InvalidJoseHeaderError('Invalid Unprotected JOSE Header Parameter "b64".');
    }
  }

  const headerParameters = {
    ...(headers.protectedHeader ?? {}),
    ...(headers.unprotectedHeader ?? {}),
  } as JsonWebSignatureHeaderParameters;

  return await createJsonWebSignatureHeader(headerParameters);
}

function validateOptions(options: FlattenedJsonWebSignatureSerializationOptions): void {
  if (!isPlainObject(options)) {
    throw new TypeError('The provided options is invalid.');
  }

  if ('jwk' in options && options.jwk !== null && !(options.jwk instanceof JsonWebKey)) {
    throw new TypeError('The provided option "jwk" is invalid.');
  }

  if ('detached' in options && typeof options.detached !== 'boolean') {
    throw new TypeError('The provided option "detached" is invalid.');
  }
}
// #endregion
