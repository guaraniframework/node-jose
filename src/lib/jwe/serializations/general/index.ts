import { decode } from './decode';
import { deserialize } from './deserialize';
import { serialize } from './serialize';

interface GeneralJsonWebEncryptionMethods {
  /**
   * Decodes the provided General JSON Web Encryption Token into its Parameters.
   *
   * @param token General JSON Web Encryption Token.
   * @throws {TypeError} The provided General JSON Web Encryption Token is invalid.
   * @throws {InvalidJsonWebEncryptionError} Failed to decode the provided General JSON Web Encryption Token.
   * @returns General JSON Web Encryption Parameters.
   */
  readonly decode: typeof decode;

  /**
   * Deserializes the provided General JSON Web Encryption Token.
   *
   * @param token General JSON Web Encryption Token.
   * @param options General JSON Web Encryption deserialization options.
   * @throws {TypeError} One of the provided arguments is invalid.
   * @throws {InvalidJoseHeaderError} The JSON Web Encryption Header Parameters of the provided General JSON Web Encryption Token are invalid.
   * @throws {InvalidJsonWebEncryptionError} Failed to deserialize the General JSON Web Encryption.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to deserialize the General JSON Web Encryption Token.
   * @returns General JSON Web Encryption.
   */
  readonly deserialize: typeof deserialize;

  /**
   * Serializes the provided JSON Web Encryption Parameters into a General Token.
   *
   * @param plaintext JSON Web Encryption Plaintext.
   * @param headers JSON Web Encryption Headers Parameters.
   * @param options General JSON Web Encryption serialization options.
   * @throws {TypeError} One of the provided arguments is invalid.
   * @throws {InvalidJoseHeaderError} One of the provided JSON Web Encryption Header Parameters is invalid.
   * @throws {InvalidJsonWebEncryptionError} Failed to serialize the General JSON Web Encryption.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used to serialize the General JSON Web Encryption.
   * @returns General JSON Web Encryption Token.
   */
  readonly serialize: typeof serialize;
}

export const general: GeneralJsonWebEncryptionMethods = {
  decode,
  deserialize,
  serialize,
};
