import { JsonWebEncryptionHeader } from '../../jsonwebencryption-header';

/**
 * Compact JSON Web Encryption Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-7.1|RFC 7516 JWE Compact Serialization}
 */
export interface CompactJsonWebEncryptionParameters {
  /**
   * JSON Web Encryption Protected Header.
   */
  readonly protectedHeader: JsonWebEncryptionHeader;

  /**
   * JSON Web Encryption Encrypted Key.
   */
  readonly encryptedKey: Buffer;

  /**
   * JSON Web Encryption Initialization Vector.
   */
  readonly initializationVector: Buffer;

  /**
   * JSON Web Encryption Ciphertext.
   */
  readonly ciphertext?: Buffer;

  /**
   * JSON Web Encryption Authentication Tag.
   */
  readonly authenticationTag: Buffer;

  /**
   * JSON Web Encryption Additional Authenticated Data.
   */
  readonly additionalAuthenticatedData: Buffer;
}
