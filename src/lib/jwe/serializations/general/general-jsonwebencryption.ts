import { Buffer } from 'buffer';

import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { GeneralJsonWebEncryptionRecipient } from './general-jsonwebencryption-recipient';

/**
 * General JSON Web Encryption.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-7.2.1|RFC 7516 General JWE JSON Serialization Syntax}
 */
export interface GeneralJsonWebEncryption {
  /**
   * JSON Web Encryption Plaintext.
   */
  readonly plaintext: Buffer;

  /**
   * JSON Web Encryption Protected Header.
   */
  readonly protectedHeader?: Partial<JsonWebEncryptionHeaderParameters>;

  /**
   * JSON Web Encryption Unprotected Header.
   */
  readonly unprotectedHeader?: Partial<JsonWebEncryptionHeaderParameters>;

  /**
   * JSON Web Encryption Recipients.
   */
  readonly recipients: GeneralJsonWebEncryptionRecipient[];
}
