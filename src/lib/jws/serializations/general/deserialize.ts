import { Buffer } from 'buffer';

import { isPlainObject } from '@guarani/primitives';

import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { DigitalSignatureAlgorithm } from '../../../jwa/jws/digital-signature-algorithm.type';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { JsonWebSignatureHeader } from '../../jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { decode } from './decode';
import { GeneralJsonWebSignature } from './general-jsonwebsignature';
import { GeneralJsonWebSignatureToken } from './general-jsonwebsignature.token';
import { GeneralJsonWebSignatureDeserializationOptions } from './general-jsonwebsignature-deserialization.options';
import { GeneralJsonWebSignatureParametersSignature } from './general-jsonwebsignature-parameters-signature';
import { GeneralJsonWebSignatureParsedHeaders } from './general-jsonwebsignature-parsed-headers';

/**
 * Deserializes the provided General JSON Web Signature Token.
 *
 * @param token General JSON Web Signature Token.
 * @param options General JSON Web Signature deserialization options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @throws {InvalidJoseHeaderError} The JSON Web Signature Header Parameters of the provided General JSON Web Signature Token are invalid.
 * @throws {InvalidJsonWebSignatureError} Failed to deserialize the General JSON Web Signature.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the General JSON Web Signature Token.
 * @returns General JSON Web Signature.
 */
export async function deserialize(
  token: GeneralJsonWebSignatureToken,
  options: GeneralJsonWebSignatureDeserializationOptions = {},
): Promise<GeneralJsonWebSignature> {
  let { payload, signatures } = await decode(token);

  validateOptions(options, signatures);
  validateDetachedPayload(payload, options.detachedPayload);

  payload ??= options.detachedPayload!;

  const headersPromises: Promise<GeneralJsonWebSignatureParsedHeaders>[] = [];

  for (let i = 0; i < signatures.length; i++) {
    headersPromises.push(
      (async () => {
        const { header, protectedHeader, signature, unprotectedHeader } = signatures[i]!;
        const { expectedDigitalSignatureAlgorithms, jwk } = options.signatures?.[i] ?? {};

        if (jwk === null || jwk instanceof JsonWebKey) {
          header.jsonWebKey = jwk;
        }

        const { digitalSignatureBackend, jsonWebKey, parameters } = header;

        validateExpectedAlgorithms(expectedDigitalSignatureAlgorithms, parameters);

        const encodedProtectedHeader = token.signatures[i]!.protected ?? '';
        const encodedPayload = payload.toString(parameters.b64 === false ? 'utf8' : 'base64url');

        const message =
          parameters.b64 === false
            ? Buffer.concat([Buffer.from(`${encodedProtectedHeader}.`, 'ascii'), payload])
            : Buffer.from(`${encodedProtectedHeader}.${encodedPayload}`, 'ascii');

        await digitalSignatureBackend.verify(signature, message, jsonWebKey);

        const parsedHeaders: GeneralJsonWebSignatureParsedHeaders = { header };

        if ('protectedHeader' in signatures[i]!) {
          Reflect.set(parsedHeaders, 'protectedHeader', protectedHeader);
        }

        if ('unprotectedHeader' in signatures[i]!) {
          Reflect.set(parsedHeaders, 'unprotectedHeader', unprotectedHeader);
        }

        return parsedHeaders;
      })(),
    );
  }

  return { headers: await Promise.all(headersPromises), payload };
}

// #region Helper Methods.
function validateOptions(
  options: GeneralJsonWebSignatureDeserializationOptions,
  signatures: GeneralJsonWebSignatureParametersSignature[],
): void {
  if (!isPlainObject(options)) {
    throw new TypeError('The provided options is invalid.');
  }

  if (
    'detachedPayload' in options &&
    (!Buffer.isBuffer(options.detachedPayload) || options.detachedPayload.byteLength === 0)
  ) {
    throw new TypeError('The provided option "detachedPayload" is invalid.');
  }

  if ('signatures' in options) {
    if (
      !Array.isArray(options.signatures) ||
      options.signatures.length === 0 ||
      options.signatures.some((signatureOptions) => !isPlainObject(signatureOptions))
    ) {
      throw new TypeError('The provided option "signatures" is invalid.');
    }

    options.signatures.forEach((signatureOptions) => {
      if ('jwk' in signatureOptions && signatureOptions.jwk !== null && !(signatureOptions.jwk instanceof JsonWebKey)) {
        throw new TypeError('The provided signature option "jwk" is invalid.');
      }

      if (
        'expectedDigitalSignatureAlgorithms' in signatureOptions &&
        (!Array.isArray(signatureOptions.expectedDigitalSignatureAlgorithms) ||
          signatureOptions.expectedDigitalSignatureAlgorithms.length === 0 ||
          signatureOptions.expectedDigitalSignatureAlgorithms.some((algorithm) => {
            return !JsonWebSignatureHeader.digitalSignatureAlgorithms.includes(algorithm);
          }))
      ) {
        throw new TypeError('The provided signature option "expectedDigitalSignatureAlgorithms" is invalid.');
      }
    });

    if (options.signatures.length !== signatures.length) {
      throw new TypeError(
        'The length of the option "signatures" and the General JSON Web Signature Token Signatures do not match.',
      );
    }
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
