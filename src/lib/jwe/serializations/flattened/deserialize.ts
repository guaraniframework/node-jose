import { Buffer } from 'buffer';

import { isPlainObject } from '@guarani/primitives';

import { InvalidJsonWebEncryptionError } from '../../../errors/invalid-jsonwebencryption.error';
import { KeyManagementAlgorithm } from '../../../jwa/jwe/alg/key-management-algorithm.type';
import { ContentEncryptionAlgorithm } from '../../../jwa/jwe/enc/content-encryption-algorithm.type';
import { CompressionAlgorithm } from '../../../jwa/jwe/zip/compression-algorithm.type';
import { JsonWebEncryptionCompressionBackend } from '../../../jwa/jwe/zip/jsonwebencryption-compression.backend';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { JsonWebEncryptionHeader } from '../../jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { decode } from './decode';
import { FlattenedJsonWebEncryption } from './flattened-jsonwebencryption';
import { FlattenedJsonWebEncryptionToken } from './flattened-jsonwebencryption.token';
import { FlattenedJsonWebEncryptionDeserializationOptions } from './flattened-jsonwebencryption-deserialization.options';

/**
 * Deserializes the provided Flattened JSON Web Encryption Token.
 *
 * @param token Flattened JSON Web Encryption Token.
 * @param options Flattened JSON Web Encryption deserialization options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @throws {InvalidJoseHeaderError} The JSON Web Encryption Header Parameters of the provided Flattened JSON Web Encryption Token are invalid.
 * @throws {InvalidJsonWebEncryptionError} Failed to deserialize the Flattened JSON Web Encryption.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Flattened JSON Web Encryption Token.
 * @returns Flattened JSON Web Encryption.
 */
export async function deserialize(
  token: FlattenedJsonWebEncryptionToken,
  options: FlattenedJsonWebEncryptionDeserializationOptions = {},
): Promise<FlattenedJsonWebEncryption> {
  validateOptions(options);

  let {
    additionalAuthenticatedData,
    authenticationTag,
    ciphertext,
    encryptedKey,
    header,
    initializationVector,
    protectedHeader,
    recipientUnprotectedHeader,
    unprotectedHeader,
  } = await decode(token);

  validateDetachedCiphertext(ciphertext, options.detachedCiphertext);

  if (options.jsonWebKey instanceof JsonWebKey) {
    header.jsonWebKey = options.jsonWebKey;
  }

  const { compressionBackend, contentEncryptionBackend, jsonWebKey, keyManagementBackend, parameters } = header;

  validateExpectedAlgorithms(
    options.expectedKeyManagementAlgorithms,
    options.expectedContentEncryptionAlgorithms,
    options.expectedCompressionAlgorithms,
    parameters,
  );

  const aadHeader = 'protected' in token ? Buffer.from(token.protected, 'ascii') : Buffer.alloc(0);

  encryptedKey ??= Buffer.alloc(0);

  additionalAuthenticatedData = Buffer.isBuffer(additionalAuthenticatedData)
    ? Buffer.concat([
        aadHeader,
        Buffer.from('.', 'ascii'),
        Buffer.from(additionalAuthenticatedData.toString('base64url'), 'ascii'),
      ])
    : aadHeader;

  ciphertext ??= options.detachedCiphertext!;

  const contentEncryptionKey = await keyManagementBackend.unwrap(encryptedKey, jsonWebKey!, header);

  let plaintext = await contentEncryptionBackend.decrypt(
    ciphertext,
    contentEncryptionKey,
    additionalAuthenticatedData,
    initializationVector,
    authenticationTag,
  );

  if (compressionBackend instanceof JsonWebEncryptionCompressionBackend) {
    plaintext = await compressionBackend.decompress(plaintext);
  }

  const jwe: FlattenedJsonWebEncryption = { header, plaintext };

  if (isPlainObject(protectedHeader)) {
    Reflect.set(jwe, 'protectedHeader', protectedHeader);
  }

  if (isPlainObject(recipientUnprotectedHeader)) {
    Reflect.set(jwe, 'recipientUnprotectedHeader', recipientUnprotectedHeader);
  }

  if (isPlainObject(unprotectedHeader)) {
    Reflect.set(jwe, 'unprotectedHeader', unprotectedHeader);
  }

  return jwe;
}

// #region Helper Methods
function validateOptions(options: FlattenedJsonWebEncryptionDeserializationOptions): void {
  if (!isPlainObject(options)) {
    throw new TypeError('The provided options is invalid.');
  }

  if ('jsonWebKey' in options && !(options.jsonWebKey instanceof JsonWebKey)) {
    throw new TypeError('The provided option "jsonWebKey" is invalid.');
  }

  if (
    'expectedKeyManagementAlgorithms' in options &&
    (!Array.isArray(options.expectedKeyManagementAlgorithms) ||
      options.expectedKeyManagementAlgorithms.length === 0 ||
      options.expectedKeyManagementAlgorithms.some((algorithm) => {
        return !JsonWebEncryptionHeader.keyManagementAlgorithms.includes(algorithm);
      }))
  ) {
    throw new TypeError('The provided option "expectedKeyManagementAlgorithms" is invalid.');
  }

  if (
    'expectedContentEncryptionAlgorithms' in options &&
    (!Array.isArray(options.expectedContentEncryptionAlgorithms) ||
      options.expectedContentEncryptionAlgorithms.length === 0 ||
      options.expectedContentEncryptionAlgorithms.some((algorithm) => {
        return !JsonWebEncryptionHeader.contentEncryptionAlgorithms.includes(algorithm);
      }))
  ) {
    throw new TypeError('The provided option "expectedContentEncryptionAlgorithms" is invalid.');
  }

  if (
    'expectedCompressionAlgorithms' in options &&
    (!Array.isArray(options.expectedCompressionAlgorithms) ||
      options.expectedCompressionAlgorithms.length === 0 ||
      options.expectedCompressionAlgorithms.some((algorithm) => {
        return !JsonWebEncryptionHeader.compressionAlgorithms.includes(algorithm);
      }))
  ) {
    throw new TypeError('The provided option "expectedCompressionAlgorithms" is invalid.');
  }

  if (
    'detachedCiphertext' in options &&
    (!Buffer.isBuffer(options.detachedCiphertext) || options.detachedCiphertext.byteLength === 0)
  ) {
    throw new TypeError('The provided option "detachedCiphertext" is invalid.');
  }
}

function validateDetachedCiphertext(ciphertext: Buffer | undefined, detachedCiphertext: Buffer | undefined): void {
  if (!Buffer.isBuffer(ciphertext) && !Buffer.isBuffer(detachedCiphertext)) {
    throw new InvalidJsonWebEncryptionError('The JSON Web Encryption requires a valid Ciphertext.');
  }

  if (Buffer.isBuffer(ciphertext) && Buffer.isBuffer(detachedCiphertext)) {
    throw new InvalidJsonWebEncryptionError('The provided JSON Web Encryption already has a defined Ciphertext.');
  }
}

function validateExpectedAlgorithms(
  expectedKeyManagementAlgorithms: KeyManagementAlgorithm[] | undefined,
  expectedContentEncryptionAlgorithms: ContentEncryptionAlgorithm[] | undefined,
  expectedCompressionAlgorithms: CompressionAlgorithm[] | undefined,
  parameters: JsonWebEncryptionHeaderParameters,
): void {
  if (Array.isArray(expectedKeyManagementAlgorithms) && !expectedKeyManagementAlgorithms.includes(parameters.alg)) {
    throw new InvalidJsonWebEncryptionError(
      `Unexpected JSON Web Encryption Key Management Algorithm "${parameters.alg}".`,
    );
  }

  if (
    Array.isArray(expectedContentEncryptionAlgorithms) &&
    !expectedContentEncryptionAlgorithms.includes(parameters.enc)
  ) {
    throw new InvalidJsonWebEncryptionError(
      `Unexpected JSON Web Encryption Content Encryption Algorithm "${parameters.enc}".`,
    );
  }

  if (Array.isArray(expectedCompressionAlgorithms) && !expectedCompressionAlgorithms.includes(parameters.zip!)) {
    throw new InvalidJsonWebEncryptionError(
      `Unexpected JSON Web Encryption Compression Algorithm "${parameters.zip ?? ''}".`,
    );
  }
}
// #endregion
