import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';

/**
 * Flattened JSON Web Encryption Token.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-7.2.2|RFC 7516 Flattened JWE JSON Serialization Syntax}
 */
export interface FlattenedJsonWebEncryptionToken {
  /**
   * JSON Web Encryption Protected Header.
   */
  readonly protected?: string;

  /**
   * JSON Web Encryption Unprotected Header.
   */
  readonly unprotected?: Partial<JsonWebEncryptionHeaderParameters>;

  /**
   * JSON Web Encryption Recipient Unprotected Header.
   */
  readonly header?: Partial<JsonWebEncryptionHeaderParameters>;

  /**
   * JSON Web Encryption Encrypted Key.
   */
  readonly encrypted_key?: string;

  /**
   * JSON Web Encryption Additional Authenticated Data.
   */
  readonly aad?: string;

  /**
   * JSON Web Encryption Initialization Vector.
   */
  readonly iv: string;

  /**
   * JSON Web Encryption Ciphertext.
   */
  readonly ciphertext?: string;

  /**
   * JSON Web Encryption Authentication Tag.
   */
  readonly tag: string;
}
