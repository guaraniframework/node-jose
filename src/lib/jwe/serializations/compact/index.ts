import { decode } from './decode';
import { deserialize } from './deserialize';
import { serialize } from './serialize';

interface CompactJsonWebEncryptionMethods {
  /**
   * Decodes the provided Compact JSON Web Encryption Token into its Parameters.
   *
   * @param token Compact JSON Web Encryption Token.
   * @throws {TypeError} The provided Compact JSON Web Encryption Token is invalid.
   * @throws {InvalidJsonWebEncryptionError} Failed to decode the provided Compact JSON Web Encryption Token.
   * @returns Compact JSON Web Encryption Parameters.
   */
  readonly decode: typeof decode;

  /**
   * Deserializes the provided Compact JSON Web Encryption Token.
   *
   * @param token Compact JSON Web Encryption Token.
   * @param options Compact JSON Web Encryption deserialization options.
   * @throws {TypeError} One of the provided arguments is invalid.
   * @throws {InvalidJoseHeaderError} The JSON Web Encryption Header Parameters of the provided Compact JSON Web Encryption Token are invalid.
   * @throws {InvalidJsonWebEncryptionError} Failed to deserialize the Compact JSON Web Encryption.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Compact JSON Web Encryption Token.
   * @returns Compact JSON Web Encryption.
   */
  readonly deserialize: typeof deserialize;

  /**
   * Serializes the provided JSON Web Encryption Parameters into a Compact Token.
   *
   * @param plaintext JSON Web Encryption Plaintext.
   * @param protectedHeader JSON Web Encryption Protected Header Parameters.
   * @param options Compact JSON Web Encryption serialization options.
   * @throws {TypeError} One of the provided arguments is invalid.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Protected Header Parameters are invalid.
   * @throws {InvalidJsonWebEncryptionError} Failed to serialize the Compact JSON Web Encryption.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Compact JSON Web Encryption.
   * @returns Compact JSON Web Encryption Token.
   */
  readonly serialize: typeof serialize;
}

export const compact: CompactJsonWebEncryptionMethods = {
  decode,
  deserialize,
  serialize,
};
