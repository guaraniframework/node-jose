import { isNonEmptyString, jsonParse } from '@guarani/primitives';

import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { createJsonWebSignatureHeader } from '../../create-jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { CompactJsonWebSignatureParameters } from './compact-jsonwebsignature.parameters';
import { CompactJsonWebSignatureToken } from './compact-jsonwebsignature.token';

/**
 * Decodes the provided Compact JSON Web Signature Token into its Parameters.
 *
 * @param token Compact JSON Web Signature Token.
 * @throws {TypeError} The provided Compact JSON Web Signature Token is invalid.
 * @throws {InvalidJsonWebSignatureError} Failed to decode the provided Compact JSON Web Signature Token.
 * @returns Compact JSON Web Signature Parameters.
 */
export async function decode(token: string): Promise<CompactJsonWebSignatureParameters> {
  if (!isNonEmptyString(token)) {
    throw new TypeError('The provided Compact JSON Web Signature Token is invalid.');
  }

  const tokenParts = token.split('.') as CompactJsonWebSignatureToken;

  if (tokenParts.length !== 3) {
    throw new InvalidJsonWebSignatureError('The provided JSON Web Signature is invalid.');
  }

  try {
    const [encodedProtectedHeader, encodedPayload, encodedSignature] = tokenParts;

    const protectedHeaderParameters = jsonParse(
      Buffer.from(encodedProtectedHeader, 'base64url').toString('utf8'),
    ) as JsonWebSignatureHeaderParameters;

    const protectedHeader = await createJsonWebSignatureHeader(protectedHeaderParameters);
    const payload = Buffer.from(encodedPayload, protectedHeader.parameters.b64 === false ? 'utf8' : 'base64url');
    const signature = Buffer.from(encodedSignature, 'base64url');

    const parameters: CompactJsonWebSignatureParameters = { protectedHeader, signature };

    if (payload.byteLength !== 0) {
      Reflect.set(parameters, 'payload', payload);
    }

    return parameters;
  } catch (error: unknown) {
    throw new InvalidJsonWebSignatureError('The provided JSON Web Signature is invalid.', { cause: error });
  }
}
