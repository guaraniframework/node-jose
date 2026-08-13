import { Buffer } from 'buffer';

import { isPlainObject, jsonStringify } from '@guarani/primitives';

import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { DigitalSignatureAlgorithm } from '../../../jwa/jws/digital-signature-algorithm.type';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { JsonWebSignatureHeader } from '../../jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { CompactJsonWebSignature } from './compact-jsonwebsignature';
import { CompactJsonWebSignatureDeserializationOptions } from './compact-jsonwebsignature-deserialization.options';
import { decode } from './decode';

/**
 * Deserializes the provided Compact JSON Web Signature Token.
 *
 * @param token Compact JSON Web Signature Token.
 * @param options Compact JSON Web Signature deserialization options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @throws {InvalidJsonWebSignatureError} Failed to deserialize the Compact JSON Web Signature.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Compact JSON Web Signature Token.
 * @returns Compact JSON Web Signature.
 */
export async function deserialize(
  token: string,
  options: CompactJsonWebSignatureDeserializationOptions = {},
): Promise<CompactJsonWebSignature> {
  validateOptions(options);

  let { payload, protectedHeader, signature } = await decode(token);

  validateDetachedPayload(payload, options.detachedPayload);

  if (options.jsonWebKey === null || options.jsonWebKey instanceof JsonWebKey) {
    protectedHeader.jsonWebKey = options.jsonWebKey;
  }

  const { digitalSignatureBackend, jsonWebKey, parameters } = protectedHeader;

  validateExpectedAlgorithms(options.expectedDigitalSignatureAlgorithms, parameters);

  payload ??= options.detachedPayload!;

  const encodedProtectedHeader = Buffer.from(jsonStringify(parameters), 'utf8').toString('base64url');
  const encodedPayload = payload.toString(parameters.b64 === false ? 'utf8' : 'base64url');

  const message =
    parameters.b64 === false
      ? Buffer.concat([Buffer.from(`${encodedProtectedHeader}.`, 'ascii'), payload])
      : Buffer.from(`${encodedProtectedHeader}.${encodedPayload}`, 'ascii');

  await digitalSignatureBackend.verify(signature, message, jsonWebKey);

  return { payload, protectedHeader };
}

// #region Helper Methods
function validateOptions(options: CompactJsonWebSignatureDeserializationOptions): void {
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
