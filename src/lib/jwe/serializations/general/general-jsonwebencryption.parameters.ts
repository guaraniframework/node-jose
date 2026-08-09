import { Buffer } from 'buffer';

import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { GeneralJsonWebEncryptionParametersRecipient } from './general-jsonwebencryption-parameters-recipient';

/**
 * General JSON Web Encryption Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-7.2.1|RFC 7516 General JWE JSON Serialization Syntax}
 */
export interface GeneralJsonWebEncryptionParameters {
  /**
   * JSON Web Encryption Protected Header.
   */
  readonly protectedHeader?: Partial<JsonWebEncryptionHeaderParameters>;

  /**
   * JSON Web Encryption Unprotected Header.
   */
  readonly unprotectedHeader?: Partial<JsonWebEncryptionHeaderParameters>;

  /**
   * JSON Web Encryption Initialization Vector.
   */
  readonly initializationVector: Buffer;

  /**
   * JSON Web Encryption Additional Authenticated Data.
   */
  readonly additionalAuthenticatedData?: Buffer;

  /**
   * JSON Web Encryption Ciphertext.
   */
  readonly ciphertext?: Buffer;

  /**
   * JSON Web Encryption Authentication Tag.
   */
  readonly authenticationTag: Buffer;

  /**
   * JSON Web Encryption Recipients.
   */
  readonly recipients: GeneralJsonWebEncryptionParametersRecipient[];
}
