import { JsonWebEncryptionHeader } from '../../jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';

/**
 * General JSON Web Encryption Recipient.
 */
export interface GeneralJsonWebEncryptionRecipient {
  /**
   * JSON Web Encryption Header.
   */
  readonly header: JsonWebEncryptionHeader;

  /**
   * JSON Web Encryption Recipient Unprotected Header.
   */
  readonly recipientUnprotectedHeader?: Partial<JsonWebEncryptionHeaderParameters>;
}
