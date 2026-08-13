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
import { CompactJsonWebEncryption } from './compact-jsonwebencryption';
import { CompactJsonWebEncryptionDeserializationOptions } from './compact-jsonwebencryption-deserialization.options';
import { decode } from './decode';

/**
 * Deserializes the provided Compact JSON Web Encryption Token.
 *
 * @param token Compact JSON Web Encryption Token.
 * @param options Compact JSON Web Encryption deserialization options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @throws {InvalidJoseHeaderError} The JSON Web Encryption Header Parameters of the provided Compact JSON Web Encryption Token are invalid.
 * @throws {InvalidJsonWebEncryptionError} Failed to deserialize the Compact JSON Web Encryption.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Compact JSON Web Encryption Token.
 * @returns Compact JSON Web Encryption.
 */
export async function deserialize(
  token: string,
  options: CompactJsonWebEncryptionDeserializationOptions = {},
): Promise<CompactJsonWebEncryption> {
  validateOptions(options);

  let {
    additionalAuthenticatedData,
    authenticationTag,
    encryptedKey,
    initializationVector,
    protectedHeader,
    ciphertext,
  } = await decode(token);

  validateDetachedCiphertext(ciphertext, options.detachedCiphertext);

  if (options.jsonWebKey instanceof JsonWebKey) {
    protectedHeader.jsonWebKey = options.jsonWebKey;
  }

  const { compressionBackend, contentEncryptionBackend, keyManagementBackend, parameters } = protectedHeader;

  validateExpectedAlgorithms(
    options.expectedKeyManagementAlgorithms,
    options.expectedContentEncryptionAlgorithms,
    options.expectedCompressionAlgorithms,
    parameters,
  );

  ciphertext ??= options.detachedCiphertext!;

  const contentEncryptionKey = await keyManagementBackend.unwrap(
    encryptedKey,
    protectedHeader.jsonWebKey!,
    protectedHeader,
  );

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

  return { plaintext, protectedHeader };
}

// #region Helper Methods
function validateOptions(options: CompactJsonWebEncryptionDeserializationOptions): void {
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
