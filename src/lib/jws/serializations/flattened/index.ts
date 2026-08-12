import { decode } from './decode';
import { deserialize } from './deserialize';
import { serialize } from './serialize';

interface FlattenedJsonWebSignatureMethods {
  /**
   * Decodes the provided Flattened JSON Web Signature Token into its Parameters.
   *
   * @param token Flattened JSON Web Signature Token.
   * @throws {TypeError} The provided Flattened JSON Web Signature Token is invalid.
   * @throws {InvalidJsonWebSignatureError} Failed to decode the provided Flattened JSON Web Signature Token.
   * @returns Flattened JSON Web Signature Parameters.
   */
  readonly decode: typeof decode;

  /**
   * Deserializes the provided Flattened JSON Web Signature Token.
   *
   * @param token Flattened JSON Web Signature Token.
   * @param options Flattened JSON Web Signature deserialization options.
   * @throws {TypeError} One of the provided arguments is invalid.
   * @throws {InvalidJoseHeaderError} The JSON Web Signature Header Parameters of the provided Flattened JSON Web Signature Token are invalid.
   * @throws {InvalidJsonWebSignatureError} Failed to deserialize the Flattened JSON Web Signature.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the Flattened JSON Web Signature Token.
   * @returns Flattened JSON Web Signature.
   */
  readonly deserialize: typeof deserialize;

  /**
   * Serializes the provided JSON Web Signature Parameters into a Flattened Token.
   *
   * @param payload JSON Web Signature Payload.
   * @param headers JSON Web Signature Headers Parameters.
   * @param options Flattened JSON Web Signature serialization options.
   * @throws {TypeError} One of the provided arguments is invalid.
   * @throws {InvalidJoseHeaderError} One of the provided JSON Web Signature Header Parameters is invalid.
   * @throws {InvalidJsonWebSignatureError} Failed to serialize the Flattened JSON Web Signature.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the Flattened JSON Web Signature.
   * @returns Flattened JSON Web Signature Token.
   */
  readonly serialize: typeof serialize;
}

export const flattened: FlattenedJsonWebSignatureMethods = {
  decode,
  deserialize,
  serialize,
};
