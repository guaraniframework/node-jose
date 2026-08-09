import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';

/**
 * Flattened JSON Web Encryption Headers.
 */
export interface FlattenedJsonWebEncryptionHeaders {
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
}
