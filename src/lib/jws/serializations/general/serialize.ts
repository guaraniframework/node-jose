import { Buffer } from 'buffer';

import { isPlainObject, jsonStringify } from '@guarani/primitives';

import { InvalidJoseHeaderError } from '../../../errors/invalid-jose-header.error';
import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { JoseHeader } from '../../../jose/jose-header';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { createJsonWebSignatureHeader } from '../../create-jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { GeneralJsonWebSignatureHeaders } from './general-jsonwebsignature.headers';
import { GeneralJsonWebSignatureToken } from './general-jsonwebsignature.token';
import { GeneralJsonWebSignatureParsedHeaders } from './general-jsonwebsignature-parsed-headers';
import { GeneralJsonWebSignatureSerializationOptions } from './general-jsonwebsignature-serialization.options';
import { GeneralJsonWebSignatureTokenSignature } from './general-jsonwebsignature-token-signature';

/**
 * Serializes the provided JSON Web Signature Parameters into a General Token.
 *
 * @param payload JSON Web Signature Payload.
 * @param headers JSON Web Signature Headers Parameters.
 * @param options General JSON Web Signature serialization options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @throws {InvalidJoseHeaderError} One of the provided JSON Web Signature Header Parameters is invalid.
 * @throws {InvalidJsonWebSignatureError} Failed to serialize the General JSON Web Signature.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the General JSON Web Signature.
 * @returns General JSON Web Signature Token.
 */
export async function serialize(
  payload: Buffer,
  headers: GeneralJsonWebSignatureHeaders[],
  options: GeneralJsonWebSignatureSerializationOptions = {},
): Promise<GeneralJsonWebSignatureToken> {
  validatePayload(payload);
  const parsedHeadersCollection = await validateHeaders(headers);
  validateOptions(options, parsedHeadersCollection);

  const { detached, jwks } = options;
  const isPayloadUnencoded = parsedHeadersCollection[0]!.header.parameters.b64 === false;

  if (isPayloadUnencoded && payload.includes(0x2e) && detached !== true) {
    throw new InvalidJsonWebSignatureError('The provided Unencoded Payload cannot be serialized.');
  }

  const token: GeneralJsonWebSignatureToken = {
    signatures: await Promise.all(
      parsedHeadersCollection.map(async (parsedHeaders, index) => {
        const jwk = jwks?.[index];
        const jsonWebKey = jwk === null || jwk instanceof JsonWebKey ? jwk : parsedHeaders.header.jsonWebKey;

        const encodedProtectedHeader =
          'protectedHeader' in parsedHeaders
            ? Buffer.from(jsonStringify(parsedHeaders.protectedHeader), 'utf8').toString('base64url')
            : '';

        const message = isPayloadUnencoded
          ? Buffer.concat([Buffer.from(`${encodedProtectedHeader}.`, 'ascii'), payload])
          : Buffer.from(`${encodedProtectedHeader}.${payload.toString('base64url')}`, 'ascii');

        const signature = await parsedHeaders.header.digitalSignatureBackend.sign(message, jsonWebKey);

        const signaturesParameters: GeneralJsonWebSignatureTokenSignature = {
          signature: signature.toString('base64url'),
        };

        if ('protectedHeader' in parsedHeaders) {
          Reflect.set(signaturesParameters, 'protected', encodedProtectedHeader);
        }

        if ('unprotectedHeader' in parsedHeaders) {
          Reflect.set(signaturesParameters, 'header', parsedHeaders.unprotectedHeader);
        }

        return signaturesParameters;
      }),
    ),
  };

  if (detached !== true) {
    Reflect.set(token, 'payload', payload.toString(isPayloadUnencoded ? 'utf8' : 'base64url'));
  }

  return token;
}

// #region Helper Methods.
function validatePayload(payload: Buffer): void {
  if (!Buffer.isBuffer(payload) || payload.byteLength === 0) {
    throw new TypeError('The provided Payload is invalid.');
  }
}

async function validateHeaders(
  headers: GeneralJsonWebSignatureHeaders[],
): Promise<GeneralJsonWebSignatureParsedHeaders[]> {
  if (!Array.isArray(headers) || headers.length === 0 || headers.some((header) => !isPlainObject(header))) {
    throw new TypeError('The provided JSON Web Signature Headers is invalid.');
  }

  const isUnencodedHeader: boolean[] = [];

  const parsedHeadersCollection = await Promise.all(
    headers.map(async (header) => {
      if ('protectedHeader' in header && !JoseHeader.isJoseHeaderParameters(header.protectedHeader)) {
        throw new TypeError('The provided JSON Web Signature Protected Header is invalid.');
      }

      if ('unprotectedHeader' in header && !JoseHeader.isJoseHeaderParameters(header.unprotectedHeader)) {
        throw new TypeError('The provided JSON Web Signature Unprotected Header is invalid.');
      }

      if (!('protectedHeader' in header) && !('unprotectedHeader' in header)) {
        throw new InvalidJoseHeaderError('Missing at least one required JSON Web Signature Header.');
      }

      if (
        !new Set(Object.keys(header.protectedHeader ?? {})).isDisjointFrom(
          new Set(Object.keys(header.unprotectedHeader ?? {})),
        )
      ) {
        throw new InvalidJoseHeaderError('Cannot have repeated JSON Web Signature Header Parameters.');
      }

      if ('unprotectedHeader' in header) {
        if ('crit' in header.unprotectedHeader) {
          throw new InvalidJoseHeaderError('Invalid Unprotected JOSE Header Parameter "crit".');
        }

        if ('b64' in header.unprotectedHeader) {
          throw new InvalidJoseHeaderError('Invalid Unprotected JOSE Header Parameter "b64".');
        }
      }

      const headerParameters = {
        ...(header.protectedHeader ?? {}),
        ...(header.unprotectedHeader ?? {}),
      } as JsonWebSignatureHeaderParameters;

      const parsedHeaders: GeneralJsonWebSignatureParsedHeaders = {
        header: await createJsonWebSignatureHeader(headerParameters),
      };

      isUnencodedHeader.push(headerParameters.b64 === false);

      if ('protectedHeader' in header) {
        Reflect.set(parsedHeaders, 'protectedHeader', header.protectedHeader);
      }

      if ('unprotectedHeader' in header) {
        Reflect.set(parsedHeaders, 'unprotectedHeader', header.unprotectedHeader);
      }

      return parsedHeaders;
    }),
  );

  if (isUnencodedHeader.some((result) => result !== isUnencodedHeader[0])) {
    throw new InvalidJoseHeaderError('Mismatching JSON Web Signature Headers Parameter "b64".');
  }

  return parsedHeadersCollection;
}

function validateOptions(
  options: GeneralJsonWebSignatureSerializationOptions,
  parsedHeaders: GeneralJsonWebSignatureParsedHeaders[],
): void {
  if (!isPlainObject(options)) {
    throw new TypeError('The provided options is invalid.');
  }

  if (
    'jwks' in options &&
    (!Array.isArray(options.jwks) ||
      options.jwks.length === 0 ||
      options.jwks.some((jwk) => jwk !== null && !(jwk instanceof JsonWebKey)) ||
      options.jwks.length !== parsedHeaders.length)
  ) {
    throw new TypeError('The provided option "jwks" is invalid.');
  }

  if ('detached' in options && typeof options.detached !== 'boolean') {
    throw new TypeError('The provided option "detached" is invalid.');
  }
}
// #endregion
