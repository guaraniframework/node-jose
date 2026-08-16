import { Buffer } from 'buffer';

import { isNonEmptyString, jsonParse } from '@guarani/primitives';

import { InvalidJsonWebTokenError } from '../../../errors/invalid-jsonwebtoken.error';
import { JsonWebSignatureHeader } from '../../../jws/jsonwebsignature-header';
import { jws } from '../../../jws/serializations';
import { JsonWebTokenClaims } from '../../jsonwebtoken-claims';
import { JsonWebTokenClaimsParameters } from '../../jsonwebtoken-claims.parameters';
import { SignedJsonWebTokenParameters } from './signed-jsonwebtoken.parameters';

/**
 * Decodes the provided Signed JSON Web Token into its Parameters.
 *
 * @param token Signed JSON Web Token.
 * @throws {TypeError} The provided Signed JSON Web Token is invalid.
 * @throws {InvalidJsonWebTokenError} Failed to decode the provided Signed JSON Web Token.
 * @throws {InvalidJsonWebTokenClaimsError} The JSON Web Token Claims of the provided Signed JSON Web Token are invalid.
 * @returns Signed JSON Web Token Parameters.
 */
export async function decode(token: string): Promise<SignedJsonWebTokenParameters> {
  if (!isNonEmptyString(token)) {
    throw new TypeError('The provided Signed JSON Web Token is invalid.');
  }

  let protectedHeader!: JsonWebSignatureHeader;
  let payload: Buffer | undefined;
  let signature!: Buffer;

  let claimsParameters: JsonWebTokenClaimsParameters;

  try {
    ({ payload, protectedHeader, signature } = await jws.compact.decode(token));

    claimsParameters = jsonParse(payload!.toString('utf8')) as JsonWebTokenClaimsParameters;
  } catch (error: unknown) {
    throw new InvalidJsonWebTokenError('The provided JSON Web Token is invalid.', { cause: error });
  }

  const claims = new JsonWebTokenClaims(claimsParameters);

  return { header: protectedHeader, claims, signature };
}
