import { Buffer } from 'buffer';
import { randomBytes } from 'crypto';
import { promisify } from 'util';

import { isPlainObject, jsonStringify } from '@guarani/primitives';

import { InvalidJoseHeaderError } from '../../../errors/invalid-jose-header.error';
import { JoseHeader } from '../../../jose/jose-header';
import { JsonWebEncryptionCompressionBackend } from '../../../jwa/jwe/zip/jsonwebencryption-compression.backend';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { createJsonWebEncryptionHeader } from '../../create-jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { GeneralJsonWebEncryptionHeaders } from './general-jsonwebencryption.headers';
import { GeneralJsonWebEncryptionToken } from './general-jsonwebencryption.token';
import { GeneralJsonWebEncryptionRecipient } from './general-jsonwebencryption-recipient';
import { GeneralJsonWebEncryptionSerializationOptions } from './general-jsonwebencryption-serialization.options';
import { GeneralJsonWebEncryptionTokenRecipient } from './general-jsonwebencryption-token-recipient';

const randomBytesAsync = promisify(randomBytes);

/**
 * Serializes the provided JSON Web Encryption Parameters into a General Token.
 *
 * @param plaintext JSON Web Encryption Plaintext.
 * @param headers JSON Web Encryption Headers Parameters.
 * @param options General JSON Web Encryption serialization options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @throws {InvalidJoseHeaderError} One of the provided JSON Web Encryption Header Parameters is invalid.
 * @throws {InvalidJsonWebEncryptionError} Failed to serialize the General JSON Web Encryption.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the General JSON Web Encryption.
 * @returns General JSON Web Encryption Token.
 */
export async function serialize(
  plaintext: Buffer,
  headers: GeneralJsonWebEncryptionHeaders,
  options: GeneralJsonWebEncryptionSerializationOptions = {},
): Promise<GeneralJsonWebEncryptionToken> {
  validatePlaintext(plaintext);
  const recipients = await validateHeaders(headers);
  validateOptions(options, recipients);

  const header = recipients[0]!.header;

  const { aad, detached, jwks } = options;
  const { compressionBackend, contentEncryptionBackend } = header;

  const contentEncryptionKey = await randomBytesAsync(header.contentEncryptionBackend.cekSize);

  const encodedProtectedHeader =
    'protectedHeader' in headers
      ? Buffer.from(jsonStringify(headers.protectedHeader), 'utf8').toString('base64url')
      : '';

  let additionalAuthenticatedData = Buffer.from(encodedProtectedHeader, 'ascii');

  if (Buffer.isBuffer(aad)) {
    additionalAuthenticatedData = Buffer.concat([
      additionalAuthenticatedData,
      Buffer.from('.', 'ascii'),
      Buffer.from(aad.toString('base64url'), 'ascii'),
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

  const tokenRecipients = await Promise.all(
    recipients.map<Promise<GeneralJsonWebEncryptionTokenRecipient>>(async (recipient, index) => {
      const jsonWebKey = jwks?.[index] ?? recipient.header.jsonWebKey!;

      const encryptedKey = await recipient.header.keyManagementBackend.wrap(
        contentEncryptionKey,
        jsonWebKey,
        recipient.header,
      );

      const recipientParameters: GeneralJsonWebEncryptionTokenRecipient = {
        encrypted_key: encryptedKey.toString('base64url'),
      };

      if ('recipientUnprotectedHeader' in recipient) {
        Reflect.set(recipientParameters, 'header', recipient.recipientUnprotectedHeader);
      }

      return recipientParameters;
    }),
  );

  const token: GeneralJsonWebEncryptionToken = {
    iv: initializationVector.toString('base64url'),
    tag: authenticationTag.toString('base64url'),
    recipients: tokenRecipients,
  };

  if ('protectedHeader' in headers) {
    Reflect.set(token, 'protected', encodedProtectedHeader);
  }

  if ('unprotectedHeader' in headers) {
    Reflect.set(token, 'unprotected', headers.unprotectedHeader);
  }

  if (additionalAuthenticatedData.byteLength !== 0) {
    Reflect.set(token, 'aad', additionalAuthenticatedData.toString('ascii'));
  }

  if (detached !== true) {
    Reflect.set(token, 'ciphertext', ciphertext.toString('base64url'));
  }

  return token;
}

// #region Helper Methods.
function validatePlaintext(plaintext: Buffer): void {
  if (!Buffer.isBuffer(plaintext) || plaintext.byteLength === 0) {
    throw new TypeError('The provided Plaintext is invalid.');
  }
}

async function validateHeaders(headers: GeneralJsonWebEncryptionHeaders): Promise<GeneralJsonWebEncryptionRecipient[]> {
  if ('protectedHeader' in headers && !JoseHeader.isJoseHeaderParameters(headers.protectedHeader)) {
    throw new TypeError('The provided JSON Web Encryption Protected Header is invalid.');
  }

  if ('unprotectedHeader' in headers && !JoseHeader.isJoseHeaderParameters(headers.unprotectedHeader)) {
    throw new TypeError('The provided JSON Web Encryption Unprotected Header is invalid.');
  }

  if (
    !Array.isArray(headers.recipients) ||
    headers.recipients.length === 0 ||
    headers.recipients.some((recipient) => !isPlainObject(recipient))
  ) {
    throw new TypeError('The provided JSON Web Encryption Recipients is invalid.');
  }

  const recipients = await Promise.all(
    headers.recipients.map<Promise<GeneralJsonWebEncryptionRecipient>>(async (recipient) => {
      if (
        'recipientUnprotectedHeader' in recipient &&
        !JoseHeader.isJoseHeaderParameters(recipient.recipientUnprotectedHeader)
      ) {
        throw new TypeError('The provided JSON Web Encryption Recipient Unprotected Header is invalid.');
      }

      if (
        !('protectedHeader' in headers) &&
        !('unprotectedHeader' in headers) &&
        !('recipientUnprotectedHeader' in recipient)
      ) {
        throw new InvalidJoseHeaderError('Missing at least one required JSON Web Encryption Header.');
      }

      const headerKeys = [
        ...Object.keys(headers.protectedHeader ?? {}),
        ...Object.keys(headers.unprotectedHeader ?? {}),
        ...Object.keys(recipient.recipientUnprotectedHeader ?? {}),
      ];

      if (headerKeys.length !== new Set(headerKeys).size) {
        throw new InvalidJoseHeaderError('Cannot have repeated JSON Web Encryption Header Parameters.');
      }

      const headerParameters = {
        ...(headers.protectedHeader ?? {}),
        ...(headers.unprotectedHeader ?? {}),
        ...(recipient.recipientUnprotectedHeader ?? {}),
      } as JsonWebEncryptionHeaderParameters;

      if (headerParameters.alg === 'ECDH-ES' || headerParameters.alg === 'dir') {
        throw new InvalidJoseHeaderError(
          'Cannot use the JSON Web Encryption Key Management Algorithms "ECDH-ES" and "dir" with General JSON Web Encryption Serializations.',
        );
      }

      const jweRecipient: GeneralJsonWebEncryptionRecipient = {
        header: await createJsonWebEncryptionHeader(headerParameters),
      };

      if ('recipientUnprotectedHeader' in recipient) {
        Reflect.set(jweRecipient, 'recipientUnprotectedHeader', recipient.recipientUnprotectedHeader);
      }

      return jweRecipient;
    }),
  );

  if (new Set(recipients.map((recipient) => recipient.header.parameters.enc)).size > 1) {
    throw new InvalidJoseHeaderError('Cannot have distinct JSON Web Encryption Content Encryption Algorithms.');
  }

  const zipCounts = recipients.filter((recipient) => {
    return recipient.header.compressionBackend instanceof JsonWebEncryptionCompressionBackend;
  }).length;

  if (zipCounts !== 0 && zipCounts !== recipients.length) {
    throw new InvalidJoseHeaderError('Cannot have distinct JSON Web Encryption Compression Algorithms.');
  }

  return recipients;
}

function validateOptions(
  options: GeneralJsonWebEncryptionSerializationOptions,
  recipients: GeneralJsonWebEncryptionRecipient[],
): void {
  if (!isPlainObject(options)) {
    throw new TypeError('The provided options is invalid.');
  }

  if ('aad' in options && (!Buffer.isBuffer(options.aad) || options.aad.byteLength === 0)) {
    throw new TypeError('The provided option "aad" is invalid.');
  }

  if (
    'jwks' in options &&
    (!Array.isArray(options.jwks) ||
      options.jwks.length === 0 ||
      options.jwks.some((jwk) => !(jwk instanceof JsonWebKey)) ||
      options.jwks.length !== recipients.length)
  ) {
    throw new TypeError('The provided option "jwks" is invalid.');
  }

  if ('detached' in options && typeof options.detached !== 'boolean') {
    throw new TypeError('The provided option "detached" is invalid.');
  }
}
// #endregion
