import { Buffer } from 'buffer';

import { isPlainObject, jsonStringify } from '@guarani/primitives';

import { InvalidJoseHeaderError } from '../../../errors/invalid-jose-header.error';
import { JoseHeader } from '../../../jose/jose-header';
import { JsonWebEncryptionCompressionBackend } from '../../../jwa/jwe/zip/jsonwebencryption-compression.backend';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { createJsonWebEncryptionHeader } from '../../create-jsonwebencryption-header';
import { JsonWebEncryptionHeader } from '../../jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { FlattenedJsonWebEncryptionHeaders } from './flattened-jsonwebencryption.headers';
import { FlattenedJsonWebEncryptionToken } from './flattened-jsonwebencryption.token';
import { FlattenedJsonWebEncryptionSerializationOptions } from './flattened-jsonwebencryption-serialization.options';

/**
 * Serializes the provided JSON Web Encryption Parameters into a Flattened Token.
 *
 * @param plaintext JSON Web Encryption Plaintext.
 * @param headers JSON Web Encryption Headers Parameters.
 * @param options Flattened JSON Web Encryption serialization options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @throws {InvalidJoseHeaderError} One of the provided JSON Web Encryption Header Parameters is invalid.
 * @throws {InvalidJsonWebEncryptionError} Failed to serialize the Flattened JSON Web Encryption.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Flattened JSON Web Encryption.
 * @returns Flattened JSON Web Encryption Token.
 */
export async function serialize(
  plaintext: Buffer,
  headers: FlattenedJsonWebEncryptionHeaders,
  options: FlattenedJsonWebEncryptionSerializationOptions = {},
): Promise<FlattenedJsonWebEncryptionToken> {
  validatePlaintext(plaintext);
  const header = await validateHeaders(headers);
  validateOptions(options);

  const { compressionBackend, contentEncryptionBackend, keyManagementBackend } = header;

  const jsonWebKey = options.jsonWebKey ?? header.jsonWebKey!;

  const contentEncryptionKey = await keyManagementBackend.generateContentEncryptionKey(jsonWebKey, header);
  const encryptedKey = await keyManagementBackend.wrap(contentEncryptionKey, jsonWebKey, header);

  const encodedProtectedHeader =
    'protectedHeader' in headers
      ? Buffer.from(jsonStringify(headers.protectedHeader), 'utf8').toString('base64url')
      : '';

  let additionalAuthenticatedData = Buffer.from(encodedProtectedHeader, 'ascii');

  if (Buffer.isBuffer(options.additionalAuthenticatedData)) {
    additionalAuthenticatedData = Buffer.concat([
      additionalAuthenticatedData,
      Buffer.from('.', 'ascii'),
      Buffer.from(options.additionalAuthenticatedData.toString('base64url'), 'ascii'),
    ]);
  }

  if (compressionBackend instanceof JsonWebEncryptionCompressionBackend) {
    plaintext = await compressionBackend.compress(plaintext);
  }

  const initializationVector = await contentEncryptionBackend.generateInitializationVector();

  const [ciphertext, authenticationTag] = await contentEncryptionBackend.encrypt(
    plaintext,
    contentEncryptionKey,
    additionalAuthenticatedData,
    initializationVector,
  );

  const token: FlattenedJsonWebEncryptionToken = {
    encrypted_key: encryptedKey.toString('base64url'),
    iv: initializationVector.toString('base64url'),
    tag: authenticationTag.toString('base64url'),
  };

  if ('protectedHeader' in headers) {
    Reflect.set(token, 'protected', encodedProtectedHeader);
  }

  if ('unprotectedHeader' in headers) {
    Reflect.set(token, 'unprotected', headers.unprotectedHeader);
  }

  if ('recipientUnprotectedHeader' in headers) {
    Reflect.set(token, 'header', headers.recipientUnprotectedHeader);
  }

  if (additionalAuthenticatedData.byteLength !== 0) {
    Reflect.set(token, 'aad', additionalAuthenticatedData.toString('ascii'));
  }

  if (options.detached !== true) {
    Reflect.set(token, 'ciphertext', ciphertext.toString('base64url'));
  }

  return token;
}

// #region Helper Methods
function validatePlaintext(plaintext: Buffer): void {
  if (!Buffer.isBuffer(plaintext) || plaintext.byteLength === 0) {
    throw new TypeError('The provided Plaintext is invalid.');
  }
}

async function validateHeaders(headers: FlattenedJsonWebEncryptionHeaders): Promise<JsonWebEncryptionHeader> {
  if (!isPlainObject(headers)) {
    throw new TypeError('The provided JSON Web Encryption Headers is invalid.');
  }

  if ('protectedHeader' in headers && !JoseHeader.isJoseHeaderParameters(headers.protectedHeader)) {
    throw new TypeError('The provided JSON Web Encryption Protected Header is invalid.');
  }

  if ('unprotectedHeader' in headers && !JoseHeader.isJoseHeaderParameters(headers.unprotectedHeader)) {
    throw new TypeError('The provided JSON Web Encryption Unprotected Header is invalid.');
  }

  if (
    'recipientUnprotectedHeader' in headers &&
    !JoseHeader.isJoseHeaderParameters(headers.recipientUnprotectedHeader)
  ) {
    throw new TypeError('The provided JSON Web Encryption Recipient Unprotected Header is invalid.');
  }

  if (
    !('protectedHeader' in headers) &&
    !('unprotectedHeader' in headers) &&
    !('recipientUnprotectedHeader' in headers)
  ) {
    throw new InvalidJoseHeaderError('Missing at least one required JSON Web Encryption Header.');
  }

  const headerKeys = [
    ...Object.keys(headers.protectedHeader ?? {}),
    ...Object.keys(headers.unprotectedHeader ?? {}),
    ...Object.keys(headers.recipientUnprotectedHeader ?? {}),
  ];

  if (headerKeys.length !== new Set(headerKeys).size) {
    throw new InvalidJoseHeaderError('Cannot have repeated JSON Web Encryption Header Parameters.');
  }

  const headerParameters = {
    ...(headers.protectedHeader ?? {}),
    ...(headers.unprotectedHeader ?? {}),
    ...(headers.recipientUnprotectedHeader ?? {}),
  } as JsonWebEncryptionHeaderParameters;

  return await createJsonWebEncryptionHeader(headerParameters);
}

function validateOptions(options: FlattenedJsonWebEncryptionSerializationOptions): void {
  if (!isPlainObject(options)) {
    throw new TypeError('The provided options is invalid.');
  }

  if (
    'additionalAuthenticatedData' in options &&
    (!Buffer.isBuffer(options.additionalAuthenticatedData) || options.additionalAuthenticatedData.byteLength === 0)
  ) {
    throw new TypeError('The provided option "additionalAuthenticatedData" is invalid.');
  }

  if ('jsonWebKey' in options && !(options.jsonWebKey instanceof JsonWebKey)) {
    throw new TypeError('The provided option "jsonWebKey" is invalid.');
  }

  if ('detached' in options && typeof options.detached !== 'boolean') {
    throw new TypeError('The provided option "detached" is invalid.');
  }
}
// #endregion
