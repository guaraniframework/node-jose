import { InvalidJsonWebTokenError } from '../../../errors/invalid-jsonwebtoken.error';
import { JsonWebEncryptionHeaderParameters } from '../../../jwe/jsonwebencryption-header.parameters';
import { jwe } from '../../../jwe/serializations';
import { JsonWebTokenClaims } from '../../jsonwebtoken-claims';
import { JsonWebTokenClaimsParameters } from '../../jsonwebtoken-claims.parameters';
import { EncryptedJsonWebTokenSerializationOptions } from './encrypted-jsonwebtoken-serialization.options';

/**
 * Serializes the provided JSON Web Token Parameters into an Encrypted Token.
 *
 * @param claims JSON Web Token Claims Parameters.
 * @param protectedHeader JSON Web Encryption Protected Header Parameters.
 * @param options Encrypted JSON Web Token serialization options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Protected Header Parameters are invalid.
 * @throws {InvalidJsonWebTokenClaimsError} The provied JSON Web Token Claims are invalid.
 * @throws {InvalidJsonWebTokenError} Failed to serialize the Encrypted JSON Web Token.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Encrypted JSON Web Token.
 * @returns Encrypted JSON Web Token.
 */
export async function serialize(
  claims: JsonWebTokenClaimsParameters,
  protectedHeader: JsonWebEncryptionHeaderParameters,
  options: EncryptedJsonWebTokenSerializationOptions = {},
): Promise<string> {
  const jsonWebTokenClaims = new JsonWebTokenClaims(claims);

  try {
    return await jwe.compact.serialize(jsonWebTokenClaims.toBuffer(), protectedHeader, {
      ...options,
      detached: false,
    });
  } catch (error: unknown) {
    throw new InvalidJsonWebTokenError('Failed to serialize the Encrypted JSON Web Token.', { cause: error });
  }
}
