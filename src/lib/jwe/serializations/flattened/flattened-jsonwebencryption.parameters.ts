import { Buffer } from 'buffer';

import { JsonWebEncryptionHeader } from '../../jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';

/**
 * Flattened JSON Web Encryption Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-7.2.2|RFC 7516 Flattened JWE JSON Serialization Syntax}
 */
export interface FlattenedJsonWebEncryptionParameters {
  /**
   * JSON Web Encryption Protected Header.
   */
  readonly protectedHeader?: Partial<JsonWebEncryptionHeaderParameters>;

  /**
   * JSON Web Encryption Unprotected Header.
   */
  readonly unprotectedHeader?: Partial<JsonWebEncryptionHeaderParameters>;

  /**
   * JSON Web Encryption Recipient Unprotected Header.
   */
  readonly recipientUnprotectedHeader?: Partial<JsonWebEncryptionHeaderParameters>;

  /**
   * JSON Web Encryption Header.
   */
  readonly header: JsonWebEncryptionHeader;

  /**
   * JSON Web Encryption Encrypted Key.
   */
  readonly encryptedKey?: Buffer;

  /**
   * JSON Web Encryption Additional Authenticated Data.
   */
  readonly additionalAuthenticatedData?: Buffer;

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
}
