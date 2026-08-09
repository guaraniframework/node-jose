import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';

/**
 * General JSON Web Encryption Headers Recipient.
 */
export interface GeneralJsonWebEncryptionHeadersRecipient {
  /**
   * JSON Web Encryption Recipient Unprotected Header.
   */
  readonly recipientUnprotectedHeader?: Partial<JsonWebEncryptionHeaderParameters>;
}
