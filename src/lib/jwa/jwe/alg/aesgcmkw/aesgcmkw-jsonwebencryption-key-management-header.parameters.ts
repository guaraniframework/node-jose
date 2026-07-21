import { JsonWebEncryptionHeaderParameters } from '../../../../jwe/jsonwebencryption-header.parameters';

/**
 * AES GCM Key Wrap JSON Web Encryption Header Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1|RFC 7518 Header Parameters Used for AES GCM Key Encryption}
 */
export interface AESGCMKWJsonWebEncryptionKeyManagementHeaderParameters extends JsonWebEncryptionHeaderParameters {
  /**
   * Initialization Vector.
   *
   * Base64url-encoded representation of the 96-bit IV value used for the key encryption operation.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.1|RFC 7518 "iv" (Initialization Vector) Header Parameter}
   */
  readonly iv: string;

  /**
   * Authentication Tag.
   *
   * Base64url-encoded representation of the 128-bit Authentication Tag value resulting from the key encryption operation.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.2|RFC 7518 "tag" (Authentication Tag) Header Parameter}
   */
  readonly tag: string;
}
