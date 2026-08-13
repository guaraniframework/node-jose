import { Buffer } from 'buffer';

import { isNonEmptyString, isPlainObject, jsonParse, removeNullishValues } from '@guarani/primitives';

import { InvalidJoseHeaderError } from '../../../errors/invalid-jose-header.error';
import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { JoseHeader } from '../../../jose/jose-header';
import { createJsonWebSignatureHeader } from '../../create-jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { GeneralJsonWebSignatureHeaders } from './general-jsonwebsignature.headers';
import { GeneralJsonWebSignatureParameters } from './general-jsonwebsignature.parameters';
import { GeneralJsonWebSignatureToken } from './general-jsonwebsignature.token';
import { GeneralJsonWebSignatureParametersSignature } from './general-jsonwebsignature-parameters-signature';
import { GeneralJsonWebSignatureParsedHeaders } from './general-jsonwebsignature-parsed-headers';

/**
 * Decodes the provided General JSON Web Signature Token into its Parameters.
 *
 * @param token General JSON Web Signature Token.
 * @throws {TypeError} The provided General JSON Web Signature Token is invalid.
 * @throws {InvalidJsonWebSignatureError} Failed to decode the provided General JSON Web Signature Token.
 * @returns General JSON Web Signature Parameters.
 */
export async function decode(token: GeneralJsonWebSignatureToken): Promise<GeneralJsonWebSignatureParameters> {
  if (!isPlainObject(token)) {
    throw new TypeError('The provided General JSON Web Signature Token is invalid.');
  }

  if (!isValidGeneralJsonWebSignatureToken(token)) {
    throw new InvalidJsonWebSignatureError('The provided JSON Web Signature is invalid.');
  }

  const isUnencodedHeader: boolean[] = [];

  const parameters: GeneralJsonWebSignatureParameters = {
    signatures: await Promise.all(
      token.signatures.map<Promise<GeneralJsonWebSignatureParametersSignature>>(async (signature) => {
        try {
          const headers = removeNullishValues<GeneralJsonWebSignatureHeaders>({
            protectedHeader:
              'protected' in signature
                ? jsonParse(Buffer.from(signature.protected, 'base64url').toString('utf8'))
                : undefined,
            unprotectedHeader: signature.header!,
          });

          const parsedHeader = await getJoseHeader(headers);

          isUnencodedHeader.push(parsedHeader.header.parameters.b64 === false);

          const signatureParameters: GeneralJsonWebSignatureParametersSignature = {
            header: parsedHeader.header,
            signature: Buffer.from(signature.signature, 'base64url'),
          };

          if ('protectedHeader' in parsedHeader) {
            Reflect.set(signatureParameters, 'protectedHeader', parsedHeader.protectedHeader);
          }

          if ('unprotectedHeader' in parsedHeader) {
            Reflect.set(signatureParameters, 'unprotectedHeader', parsedHeader.unprotectedHeader);
          }

          return signatureParameters;
        } catch (error: unknown) {
          throw new InvalidJsonWebSignatureError('The provided JSON Web Signature is invalid.', { cause: error });
        }
      }),
    ),
  };

  if (isUnencodedHeader.some((result) => result !== isUnencodedHeader[0])) {
    throw new InvalidJsonWebSignatureError('The provided JSON Web Signature is invalid.');
  }

  if ('payload' in token) {
    Reflect.set(
      parameters,
      'payload',
      Buffer.from(token.payload, parameters.signatures[0]!.header.parameters.b64 === false ? 'utf8' : 'base64url'),
    );
  }

  return parameters;
}

// #region Helper Methods
function isValidGeneralJsonWebSignatureToken(token: GeneralJsonWebSignatureToken): boolean {
  if ('payload' in token && !isNonEmptyString(token.payload)) {
    return false;
  }

  if (
    !Array.isArray(token.signatures) ||
    token.signatures.length === 0 ||
    token.signatures.some((signature) => !isPlainObject(signature))
  ) {
    return false;
  }

  for (const signature of token.signatures) {
    if (!('protected' in signature) && !('header' in signature)) {
      return false;
    }

    if (
      'protected' in signature &&
      (!isNonEmptyString(signature.protected) ||
        !JoseHeader.isJoseHeaderParameters(jsonParse(Buffer.from(signature.protected, 'base64url').toString('utf8'))))
    ) {
      return false;
    }

    if ('header' in signature && !JoseHeader.isJoseHeaderParameters(signature.header)) {
      return false;
    }

    if (!isNonEmptyString(signature.signature)) {
      return false;
    }
  }

  return true;
}

async function getJoseHeader(headers: GeneralJsonWebSignatureHeaders): Promise<GeneralJsonWebSignatureParsedHeaders> {
  if (
    !new Set(Object.keys(headers.protectedHeader ?? {})).isDisjointFrom(
      new Set(Object.keys(headers.unprotectedHeader ?? {})),
    )
  ) {
    throw new InvalidJoseHeaderError('Cannot have repeated JSON Web Signature Header Parameters.');
  }

  if ('unprotectedHeader' in headers) {
    if ('crit' in headers.unprotectedHeader) {
      throw new InvalidJoseHeaderError('Invalid Unprotected JOSE Header Parameter "crit".');
    }

    if ('b64' in headers.unprotectedHeader) {
      throw new InvalidJoseHeaderError('Invalid Unprotected JOSE Header Parameter "b64".');
    }
  }

  const headerParameters = {
    ...(headers.protectedHeader ?? {}),
    ...(headers.unprotectedHeader ?? {}),
  } as JsonWebSignatureHeaderParameters;

  const parsedHeader: GeneralJsonWebSignatureParsedHeaders = {
    header: await createJsonWebSignatureHeader(headerParameters),
  };

  if ('protectedHeader' in headers) {
    Reflect.set(parsedHeader, 'protectedHeader', headers.protectedHeader);
  }

  if ('unprotectedHeader' in headers) {
    Reflect.set(parsedHeader, 'unprotectedHeader', headers.unprotectedHeader);
  }

  return parsedHeader;
}
// #endregion
