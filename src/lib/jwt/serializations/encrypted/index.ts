import { decode } from './decode';
import { deserialize } from './deserialize';
import { serialize } from './serialize';

interface EncryptedJsonWebTokenMethods {
  /**
   * Decodes the provided Encrypted JSON Web Token into its Parameters.
   *
   * @param token Encrypted JSON Web Token.
   * @throws {TypeError} The provided Encrypted JSON Web Token is invalid.
   * @throws {InvalidJsonWebTokenError} Failed to decode the provided Encrypted JSON Web Token.
   * @returns Encrypted JSON Web Token Parameters.
   */
  readonly decode: typeof decode;

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
  readonly deserialize: typeof deserialize;

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
  readonly serialize: typeof serialize;
}

export const encrypted: EncryptedJsonWebTokenMethods = {
  decode,
  deserialize,
  serialize,
};
