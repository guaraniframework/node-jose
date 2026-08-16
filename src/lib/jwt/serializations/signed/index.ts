import { decode } from './decode';
import { deserialize } from './deserialize';
import { serialize } from './serialize';

interface SignedJsonWebTokenMethods {
  /**
   * Decodes the provided Signed JSON Web Token into its Parameters.
   *
   * @param token Signed JSON Web Token.
   * @throws {TypeError} The provided Signed JSON Web Token is invalid.
   * @throws {InvalidJsonWebTokenError} Failed to decode the provided Signed JSON Web Token.
   * @returns Signed JSON Web Token Parameters.
   */
  readonly decode: typeof decode;

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
  readonly deserialize: typeof deserialize;

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
  readonly serialize: typeof serialize;
}

export const signed: SignedJsonWebTokenMethods = {
  decode,
  deserialize,
  serialize,
};
