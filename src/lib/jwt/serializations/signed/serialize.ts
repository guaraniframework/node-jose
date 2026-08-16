import { InvalidJsonWebTokenError } from '../../../errors/invalid-jsonwebtoken.error';
import { JsonWebSignatureHeaderParameters } from '../../../jws/jsonwebsignature-header.parameters';
import { jws } from '../../../jws/serializations';
import { JsonWebTokenClaims } from '../../jsonwebtoken-claims';
import { JsonWebTokenClaimsParameters } from '../../jsonwebtoken-claims.parameters';
import { SignedJsonWebTokenSerializationOptions } from './signed-jsonwebtoken-serialization.options';

/**
 * Serializes the provided JSON Web Token Parameters into a Signed Token.
 *
 * @param claims JSON Web Token Claims Parameters.
 * @param protectedHeader JSON Web Signature Protected Header Parameters.
 * @param options Signed JSON Web Token serialization options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Protected Header Parameters are invalid.
 * @throws {InvalidJsonWebTokenClaimsError} The provied JSON Web Token Claims are invalid.
 * @throws {InvalidJsonWebTokenError} Failed to serialize the Signed JSON Web Token.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Signed JSON Web Token.
 * @returns Signed JSON Web Token.
 */
export async function serialize(
  claims: JsonWebTokenClaimsParameters,
  protectedHeader: JsonWebSignatureHeaderParameters,
  options: SignedJsonWebTokenSerializationOptions = {},
): Promise<string> {
  const jsonWebTokenClaims = new JsonWebTokenClaims(claims);

  try {
    return await jws.compact.serialize(jsonWebTokenClaims.toBuffer(), protectedHeader, options);
  } catch (error: unknown) {
    throw new InvalidJsonWebTokenError('Failed to serialize the Signed JSON Web Token.', { cause: error });
  }
}
