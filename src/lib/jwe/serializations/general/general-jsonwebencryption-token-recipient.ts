import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';

/**
 * General JSON Web Encryption Token Recipient.
 */
export interface GeneralJsonWebEncryptionTokenRecipient {
  /**
   * JSON Web Encryption Recipient Unprotected Header.
   */
  readonly header?: Partial<JsonWebEncryptionHeaderParameters>;

  /**
   * JSON Web Encryption Encrypted Key.
   */
  readonly encrypted_key: string;
}
