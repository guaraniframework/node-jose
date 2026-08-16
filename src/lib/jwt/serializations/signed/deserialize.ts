import { jsonParse } from '@guarani/primitives';

import { InvalidJsonWebTokenError } from '../../../errors/invalid-jsonwebtoken.error';
import { jws } from '../../../jws/serializations';
import { JsonWebTokenClaims } from '../../jsonwebtoken-claims';
import { JsonWebTokenClaimsParameters } from '../../jsonwebtoken-claims.parameters';
import { SignedJsonWebToken } from './signed-jsonwebtoken';
import { SignedJsonWebTokenDeserializationOptions } from './signed-jsonwebtoken-deserialization.options';

/**
 * Deserializes the provided Signed JSON Web Token.
 *
 * @param token Signed JSON Web Token.
 * @param options Signed JSON Web Token deserialization options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @throws {InvalidJsonWebTokenClaimsError} Failed to parse the JSON Web Token Claims.
 * @throws {InvalidJsonWebTokenError} Failed to deserialize the Signed JSON Web Token.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Signed JSON Web Token.
 * @returns Signed JSON Web Token.
 */
export async function deserialize(
  token: string,
  options: SignedJsonWebTokenDeserializationOptions = {},
): Promise<SignedJsonWebToken> {
  try {
    const { payload, protectedHeader } = await jws.compact.deserialize(token, options);
    const claimsParameters = jsonParse(payload.toString('utf8')) as JsonWebTokenClaimsParameters;

    return { claims: new JsonWebTokenClaims(claimsParameters), header: protectedHeader };
  } catch (error: unknown) {
    throw new InvalidJsonWebTokenError('The provided JSON Web Token is invalid.', { cause: error });
  }
}
