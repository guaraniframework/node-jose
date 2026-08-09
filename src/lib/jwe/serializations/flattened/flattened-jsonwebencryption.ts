import { Buffer } from 'buffer';

import { JsonWebEncryptionHeader } from '../../jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';

/**
 * Flattened JSON Web Encryption.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-7.2.2|RFC 7516 Flattened JWE JSON Serialization Syntax}
 */
export interface FlattenedJsonWebEncryption {
  /**
   * JSON Web Encryption Plaintext.
   */
  readonly plaintext: Buffer;

  /**
   * JSON Web Encryption Header.
   */
  readonly header: JsonWebEncryptionHeader;

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
