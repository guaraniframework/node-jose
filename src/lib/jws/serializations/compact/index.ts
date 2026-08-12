import { decode } from './decode';
import { deserialize } from './deserialize';
import { serialize } from './serialize';

interface CompactJsonWebSignatureMethods {
  /**
   * Decodes the provided Compact JSON Web Signature Token into its Parameters.
   *
   * @param token Compact JSON Web Signature Token.
   * @throws {TypeError} The provided Compact JSON Web Signature Token is invalid.
   * @throws {InvalidJsonWebSignatureError} Failed to decode the provided Compact JSON Web Signature Token.
   * @returns Compact JSON Web Signature Parameters.
   */
  readonly decode: typeof decode;

  /**
   * Deserializes the provided Compact JSON Web Signature Token.
   *
   * @param token Compact JSON Web Signature Token.
   * @param options Compact JSON Web Signature deserialization options.
   * @throws {TypeError} One of the provided arguments is invalid.
   * @throws {InvalidJsonWebSignatureError} Failed to deserialize the Compact JSON Web Signature.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Compact JSON Web Signature Token.
   * @returns Compact JSON Web Signature.
   */
  readonly deserialize: typeof deserialize;

  /**
   * Serializes the provided JSON Web Signature Parameters into a Compact Token.
   *
   * @param payload JSON Web Signature Payload.
   * @param protectedHeader JSON Web Signature Protected Header Parameters.
   * @param options Compact JSON Web Signature serialization options.
   * @throws {TypeError} One of the provided arguments is invalid.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Protected Header Parameters are invalid.
   * @throws {InvalidJsonWebSignatureError} Failed to serialize the Compact JSON Web Signature.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Compact JSON Web Signature.
   * @returns Compact JSON Web Signature Token.
   */
  readonly serialize: typeof serialize;
}

export const compact: CompactJsonWebSignatureMethods = {
  decode,
  deserialize,
  serialize,
};
