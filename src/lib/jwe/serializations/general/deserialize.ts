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
import { GeneralJsonWebEncryption } from './general-jsonwebencryption';
import { GeneralJsonWebEncryptionToken } from './general-jsonwebencryption.token';
import { GeneralJsonWebEncryptionDeserializationOptions } from './general-jsonwebencryption-deserialization.options';
import { GeneralJsonWebEncryptionParametersRecipient } from './general-jsonwebencryption-parameters-recipient';
import { GeneralJsonWebEncryptionRecipient } from './general-jsonwebencryption-recipient';

/**
 * Deserializes the provided General JSON Web Encryption Token.
 *
 * @param token General JSON Web Encryption Token.
 * @param options General JSON Web Encryption deserialization options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @throws {InvalidJoseHeaderError} The JSON Web Encryption Header Parameters of the provided General JSON Web Encryption Token are invalid.
 * @throws {InvalidJsonWebEncryptionError} Failed to deserialize the General JSON Web Encryption.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the General JSON Web Encryption Token.
 * @returns General JSON Web Encryption.
 */
export async function deserialize(
  token: GeneralJsonWebEncryptionToken,
  options: GeneralJsonWebEncryptionDeserializationOptions = {},
): Promise<GeneralJsonWebEncryption> {
  let {
    additionalAuthenticatedData,
    authenticationTag,
    ciphertext,
    initializationVector,
    protectedHeader,
    recipients,
    unprotectedHeader,
  } = await decode(token);

  validateOptions(options, recipients);
  validateDetachedCiphertext(ciphertext, options.detachedCiphertext);

  const aadHeader = 'protected' in token ? Buffer.from(token.protected, 'ascii') : Buffer.alloc(0);

  additionalAuthenticatedData = Buffer.isBuffer(additionalAuthenticatedData)
    ? Buffer.concat([
        aadHeader,
        Buffer.from('.', 'ascii'),
        Buffer.from(additionalAuthenticatedData.toString('base64url'), 'ascii'),
      ])
    : aadHeader;

  ciphertext ??= options.detachedCiphertext!;

  const recipientsPromises: Promise<GeneralJsonWebEncryptionRecipient>[] = [];
  const plaintexts: Buffer[] = [];

  for (let i = 0; i < recipients.length; i++) {
    recipientsPromises.push(
      (async () => {
        const { encryptedKey, header, recipientUnprotectedHeader } = recipients[i]!;

        const {
          expectedCompressionAlgorithms,
          expectedContentEncryptionAlgorithms,
          expectedKeyManagementAlgorithms,
          jwk,
        } = options.recipients?.[i] ?? {};

        if (jwk instanceof JsonWebKey) {
          header.jsonWebKey = jwk;
        }

        const { compressionBackend, contentEncryptionBackend, jsonWebKey, keyManagementBackend, parameters } = header;

        validateExpectedAlgorithms(
          expectedKeyManagementAlgorithms,
          expectedContentEncryptionAlgorithms,
          expectedCompressionAlgorithms,
          parameters,
        );

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

        plaintexts.push(plaintext);

        const recipient: GeneralJsonWebEncryptionRecipient = { header };

        if (isPlainObject(recipientUnprotectedHeader)) {
          Reflect.set(recipient, 'recipientUnprotectedHeader', recipientUnprotectedHeader);
        }

        return recipient;
      })(),
    );
  }

  const resolvedRecipients = await Promise.all(recipientsPromises);

  const jwe: GeneralJsonWebEncryption = {
    plaintext: plaintexts[0]!,
    recipients: resolvedRecipients,
  };

  if (isPlainObject(protectedHeader)) {
    Reflect.set(jwe, 'protectedHeader', protectedHeader);
  }

  if (isPlainObject(unprotectedHeader)) {
    Reflect.set(jwe, 'unprotectedHeader', unprotectedHeader);
  }

  return jwe;
}

// #region Helper Methods.
function validateOptions(
  options: GeneralJsonWebEncryptionDeserializationOptions,
  recipients: GeneralJsonWebEncryptionParametersRecipient[],
): void {
  if (!isPlainObject(options)) {
    throw new TypeError('The provided options is invalid.');
  }

  if (
    'detachedCiphertext' in options &&
    (!Buffer.isBuffer(options.detachedCiphertext) || options.detachedCiphertext.byteLength === 0)
  ) {
    throw new TypeError('The provided option "detachedCiphertext" is invalid.');
  }

  if ('recipients' in options) {
    if (
      !Array.isArray(options.recipients) ||
      options.recipients.length === 0 ||
      options.recipients.some((recipientOptions) => !isPlainObject(recipientOptions))
    ) {
      throw new TypeError('The provided option "recipients" is invalid.');
    }

    options.recipients.forEach((recipientOptions) => {
      if ('jwk' in recipientOptions && !(recipientOptions.jwk instanceof JsonWebKey)) {
        throw new TypeError('The provided recipient option "jwk" is invalid.');
      }

      if (
        'expectedKeyManagementAlgorithms' in recipientOptions &&
        (!Array.isArray(recipientOptions.expectedKeyManagementAlgorithms) ||
          recipientOptions.expectedKeyManagementAlgorithms.length === 0 ||
          recipientOptions.expectedKeyManagementAlgorithms.some((algorithm) => {
            return !JsonWebEncryptionHeader.keyManagementAlgorithms.includes(algorithm);
          }))
      ) {
        throw new TypeError('The provided recipient option "expectedKeyManagementAlgorithms" is invalid.');
      }

      if (
        'expectedContentEncryptionAlgorithms' in recipientOptions &&
        (!Array.isArray(recipientOptions.expectedContentEncryptionAlgorithms) ||
          recipientOptions.expectedContentEncryptionAlgorithms.length === 0 ||
          recipientOptions.expectedContentEncryptionAlgorithms.some((algorithm) => {
            return !JsonWebEncryptionHeader.contentEncryptionAlgorithms.includes(algorithm);
          }))
      ) {
        throw new TypeError('The provided recipient option "expectedContentEncryptionAlgorithms" is invalid.');
      }

      if (
        'expectedCompressionAlgorithms' in recipientOptions &&
        (!Array.isArray(recipientOptions.expectedCompressionAlgorithms) ||
          recipientOptions.expectedCompressionAlgorithms.length === 0 ||
          recipientOptions.expectedCompressionAlgorithms.some((algorithm) => {
            return !JsonWebEncryptionHeader.compressionAlgorithms.includes(algorithm);
          }))
      ) {
        throw new TypeError('The provided recipient option "expectedCompressionAlgorithms" is invalid.');
      }
    });

    if (options.recipients.length !== recipients.length) {
      throw new TypeError(
        'The length of the option "recipients" and the General JSON Web Encryption Token Recipients do not match.',
      );
    }
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
