import { Buffer } from 'buffer';

import { JsonWebEncryptionHeader } from '../../jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';

/**
 * General JSON Web Encryption Parameters Recipient.
 */
export interface GeneralJsonWebEncryptionParametersRecipient {
  /**
   * JSON Web Encryption Header.
   */
  readonly header: JsonWebEncryptionHeader;

  /**
   * JSON Web Encryption Recipient Unprotected Header.
   */
  readonly recipientUnprotectedHeader?: Partial<JsonWebEncryptionHeaderParameters>;

  /**
   * JSON Web Encryption Encrypted Key.
   */
  readonly encryptedKey: Buffer;
}
