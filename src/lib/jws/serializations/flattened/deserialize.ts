import { Buffer } from 'buffer';

import { isPlainObject } from '@guarani/primitives';

import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { DigitalSignatureAlgorithm } from '../../../jwa/jws/digital-signature-algorithm.type';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { JsonWebSignatureHeader } from '../../jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { decode } from './decode';
import { FlattenedJsonWebSignature } from './flattened-jsonwebsignature';
import { FlattenedJsonWebSignatureToken } from './flattened-jsonwebsignature.token';
import { FlattenedJsonWebSignatureDeserializationOptions } from './flattened-jsonwebsignature-deserialization.options';

/**
 * Deserializes the provided Flattened JSON Web Signature Token.
 *
 * @param token Flattened JSON Web Signature Token.
 * @param options Flattened JSON Web Signature deserialization options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @throws {InvalidJoseHeaderError} The JSON Web Signature Header Parameters of the provided Flattened JSON Web Signature Token are invalid.
 * @throws {InvalidJsonWebSignatureError} Failed to deserialize the Flattened JSON Web Signature.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Flattened JSON Web Signature Token.
 * @returns Flattened JSON Web Signature.
 */
export async function deserialize(
  token: FlattenedJsonWebSignatureToken,
  options: FlattenedJsonWebSignatureDeserializationOptions = {},
): Promise<FlattenedJsonWebSignature> {
  validateOptions(options);

  let { header, payload, protectedHeader, signature, unprotectedHeader } = await decode(token);

  validateDetachedPayload(payload, options.detachedPayload);

  if (options.jsonWebKey === null || options.jsonWebKey instanceof JsonWebKey) {
    header.jsonWebKey = options.jsonWebKey;
  }

  const { digitalSignatureBackend, jsonWebKey, parameters } = header;

  validateExpectedAlgorithms(options.expectedDigitalSignatureAlgorithms, parameters);

  payload ??= options.detachedPayload!;

  const encodedProtectedHeader = token.protected ?? '';
  const encodedPayload = payload.toString(parameters.b64 === false ? 'utf8' : 'base64url');

  const message =
    parameters.b64 === false
      ? Buffer.concat([Buffer.from(`${encodedProtectedHeader}.`, 'ascii'), payload])
      : Buffer.from(`${encodedProtectedHeader}.${encodedPayload}`, 'ascii');

  await digitalSignatureBackend.verify(signature, message, jsonWebKey);

  const jws: FlattenedJsonWebSignature = { header, payload };

  if (isPlainObject(protectedHeader)) {
    Reflect.set(jws, 'protectedHeader', protectedHeader);
  }

  if (isPlainObject(unprotectedHeader)) {
    Reflect.set(jws, 'unprotectedHeader', unprotectedHeader);
  }

  return jws;
}

// #region Helper Methods
function validateOptions(options: FlattenedJsonWebSignatureDeserializationOptions): void {
  if (!isPlainObject(options)) {
    throw new TypeError('The provided options is invalid.');
  }

  if ('jsonWebKey' in options && options.jsonWebKey !== null && !(options.jsonWebKey instanceof JsonWebKey)) {
    throw new TypeError('The provided option "jsonWebKey" is invalid.');
  }

  if (
    'expectedDigitalSignatureAlgorithms' in options &&
    (!Array.isArray(options.expectedDigitalSignatureAlgorithms) ||
      options.expectedDigitalSignatureAlgorithms.length === 0 ||
      options.expectedDigitalSignatureAlgorithms.some((algorithm) => {
        return !JsonWebSignatureHeader.digitalSignatureAlgorithms.includes(algorithm);
      }))
  ) {
    throw new TypeError('The provided option "expectedDigitalSignatureAlgorithms" is invalid.');
  }

  if (
    'detachedPayload' in options &&
    (!Buffer.isBuffer(options.detachedPayload) || options.detachedPayload.byteLength === 0)
  ) {
    throw new TypeError('The provided option "detachedPayload" is invalid.');
  }
}

function validateDetachedPayload(payload: Buffer | undefined, detachedPayload: Buffer | undefined): void {
  if (!Buffer.isBuffer(payload) && !Buffer.isBuffer(detachedPayload)) {
    throw new InvalidJsonWebSignatureError('The JSON Web Signature requires a valid Payload.');
  }

  if (Buffer.isBuffer(payload) && Buffer.isBuffer(detachedPayload)) {
    throw new InvalidJsonWebSignatureError('The provided JSON Web Signature already has a defined Payload.');
  }
}

function validateExpectedAlgorithms(
  expectedDigitalSignatureAlgorithms: DigitalSignatureAlgorithm[] | undefined,
  parameters: JsonWebSignatureHeaderParameters,
): void {
  if (
    Array.isArray(expectedDigitalSignatureAlgorithms) &&
    !expectedDigitalSignatureAlgorithms.includes(parameters.alg!)
  ) {
    throw new InvalidJsonWebSignatureError(
      `Unexpected JSON Web Signature Digital Signature Algorithm "${parameters.alg}".`,
    );
  }
}
// #endregion
