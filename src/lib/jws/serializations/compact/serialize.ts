import { Buffer } from 'buffer';

import { isPlainObject, jsonStringify } from '@guarani/primitives';

import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { createJsonWebSignatureHeader } from '../../create-jsonwebsignature-header';
import { JsonWebSignatureHeader } from '../../jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { CompactJsonWebSignatureSerializationOptions } from './compact-jsonwebsignature-serialization.options';

/**
 * Serializes the provided JSON Web Signature Parameters into a Compact Token.
 *
 * @param payload JSON Web Signature Payload.
 * @param protectedHeader JSON Web Signature Protected Header Parameters.
 * @param options Compact JSON Web Signature serialization options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Protected Header Parameters are invalid.
 * @throws {InvalidJsonWebSignatureError} Failed to serialize the Compact JSON Web Signature.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Compact JSON Web Signature.
 * @returns Compact JSON Web Signature Token.
 */
export async function serialize(
  payload: Buffer,
  protectedHeader: JsonWebSignatureHeaderParameters,
  options: CompactJsonWebSignatureSerializationOptions = {},
): Promise<string> {
  validatePayload(payload);
  validateProtectedHeader(protectedHeader);
  validateOptions(options);

  const header = await createJsonWebSignatureHeader(protectedHeader);

  const { detached, jwk } = options;
  const { digitalSignatureBackend, parameters } = header;

  const jsonWebKey = jwk ?? header.jsonWebKey!;

  if (parameters.b64 === false && payload.includes(0x2e) && detached !== true) {
    throw new InvalidJsonWebSignatureError('The provided Unencoded Payload cannot be serialized.');
  }

  const encodedProtectedHeader = Buffer.from(jsonStringify(parameters), 'utf8').toString('base64url');
  const encodedPayload = payload.toString(parameters.b64 === false ? 'utf8' : 'base64url');

  const message =
    parameters.b64 === false
      ? Buffer.concat([Buffer.from(`${encodedProtectedHeader}.`, 'ascii'), payload])
      : Buffer.from(`${encodedProtectedHeader}.${encodedPayload}`, 'ascii');

  const signature = await digitalSignatureBackend.sign(message, jsonWebKey);
  const encodedSignature = signature.toString('base64url');

  return `${encodedProtectedHeader}.${detached ? '' : encodedPayload}.${encodedSignature}`;
}

// #region Helper Methods.
function validatePayload(payload: Buffer): void {
  if (!Buffer.isBuffer(payload) || payload.byteLength === 0) {
    throw new TypeError('The provided Payload is invalid.');
  }
}

function validateProtectedHeader(protectedHeader: JsonWebSignatureHeaderParameters): void {
  if (!JsonWebSignatureHeader.isJoseHeaderParameters(protectedHeader)) {
    throw new TypeError('The provided JSON Web Signature Protected Header is invalid.');
  }
}

function validateOptions(options: CompactJsonWebSignatureSerializationOptions): void {
  if (!isPlainObject(options)) {
    throw new TypeError('The provided options is invalid.');
  }

  if ('jwk' in options && !(options.jwk instanceof JsonWebKey)) {
    throw new TypeError('The provided option "jwk" is invalid.');
  }

  if ('detached' in options && typeof options.detached !== 'boolean') {
    throw new TypeError('The provided option "detached" is invalid.');
  }
}
// #endregion
