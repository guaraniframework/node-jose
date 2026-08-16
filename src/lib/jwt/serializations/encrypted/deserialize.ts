import { jsonParse } from '@guarani/primitives';

import { InvalidJsonWebTokenError } from '../../../errors/invalid-jsonwebtoken.error';
import { jwe } from '../../../jwe/serializations';
import { JsonWebTokenClaims } from '../../jsonwebtoken-claims';
import { JsonWebTokenClaimsParameters } from '../../jsonwebtoken-claims.parameters';
import { EncryptedJsonWebToken } from './encrypted-jsonwebtoken';
import { EncryptedJsonWebTokenDeserializationOptions } from './encrypted-jsonwebtoken-deserialization.options';

/**
 * Deserializes the provided Encrypted JSON Web Token.
 *
 * @param token Encrypted JSON Web Token.
 * @param options Encrypted JSON Web Token deserialization options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @throws {InvalidJsonWebTokenClaimsError} Failed to parse the JSON Web Token Claims.
 * @throws {InvalidJsonWebTokenError} Failed to deserialize the Encrypted JSON Web Token.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Encrypted JSON Web Token.
 * @returns Encrypted JSON Web Token.
 */
export async function deserialize(
  token: string,
  options: EncryptedJsonWebTokenDeserializationOptions = {},
): Promise<EncryptedJsonWebToken> {
  try {
    const { plaintext, protectedHeader } = await jwe.compact.deserialize(token, options);
    const claimsParameters = jsonParse(plaintext.toString('utf8')) as JsonWebTokenClaimsParameters;

    return { claims: new JsonWebTokenClaims(claimsParameters), header: protectedHeader };
  } catch (error: unknown) {
    throw new InvalidJsonWebTokenError('The provided JSON Web Token is invalid.', { cause: error });
  }
}
