import { Buffer } from 'buffer';

import { isPlainObject, jsonStringify } from '@guarani/primitives';

import { JoseHeader } from '../../../jose/jose-header';
import { JsonWebEncryptionCompressionBackend } from '../../../jwa/jwe/zip/jsonwebencryption-compression.backend';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { createJsonWebEncryptionHeader } from '../../create-jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { CompactJsonWebEncryptionSerializationOptions } from './compact-jsonwebencryption-serialization.options';

/**
 * Serializes the provided JSON Web Encryption Parameters into a Compact Token.
 *
 * @param plaintext JSON Web Encryption Plaintext.
 * @param protectedHeader JSON Web Encryption Protected Header Parameters.
 * @param options Compact JSON Web Encryption serialization options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Protected Header Parameters are invalid.
 * @throws {InvalidJsonWebEncryptionError} Failed to serialize the Compact JSON Web Encryption.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Compact JSON Web Encryption.
 * @returns Compact JSON Web Encryption Token.
 */
export async function serialize(
  plaintext: Buffer,
  protectedHeader: JsonWebEncryptionHeaderParameters,
  options: CompactJsonWebEncryptionSerializationOptions = {},
): Promise<string> {
  validatePlaintext(plaintext);
  validateProtectedHeader(protectedHeader);
  validateOptions(options);

  const header = await createJsonWebEncryptionHeader(protectedHeader);

  const { detached, jwk } = options;
  const { compressionBackend, contentEncryptionBackend, keyManagementBackend, parameters } = header;

  const jsonWebKey = jwk ?? header.jsonWebKey!;

  const contentEncryptionKey = await keyManagementBackend.generateContentEncryptionKey(jsonWebKey, header);
  const encryptedKey = await keyManagementBackend.wrap(contentEncryptionKey, jsonWebKey, header);

  const encodedProtectedHeader = Buffer.from(jsonStringify(parameters), 'utf8').toString('base64url');
  const additionalAuthenticatedData = Buffer.from(encodedProtectedHeader, 'ascii');

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

  const encodedEncryptedKey = encryptedKey.toString('base64url');
  const encodedInitializationVector = initializationVector.toString('base64url');
  const encodedCiphertext = ciphertext.toString('base64url');
  const encodedAuthenticationTag = authenticationTag.toString('base64url');

  return [
    encodedProtectedHeader,
    encodedEncryptedKey,
    encodedInitializationVector,
    detached === true ? '' : encodedCiphertext,
    encodedAuthenticationTag,
  ].join('.');
}

// #region Helper Methods.
function validatePlaintext(plaintext: Buffer): void {
  if (!Buffer.isBuffer(plaintext) || plaintext.byteLength === 0) {
    throw new TypeError('The provided Plaintext is invalid.');
  }
}

function validateProtectedHeader(protectedHeader: JsonWebEncryptionHeaderParameters): void {
  if (!JoseHeader.isJoseHeaderParameters(protectedHeader)) {
    throw new TypeError('The provided JSON Web Encryption Protected Header is invalid.');
  }
}

function validateOptions(options: CompactJsonWebEncryptionSerializationOptions): void {
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
