import { JsonWebEncryptionHeaderParameters } from '../../../../jwe/jsonwebencryption-header.parameters';

/**
 * PBES2 JSON Web Encryption Header Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1|RFC 7518 Header Parameters Used for PBES2 Key Encryption}
 */
export interface PBES2JsonWebEncryptionKeyManagementHeaderParameters extends JsonWebEncryptionHeaderParameters {
  /**
   * PBES2 Salt Input.
   *
   * Encodes a Salt Input value, which is used as part of the PBKDF2 salt value.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1.1|RFC 7518 "p2s" (PBES2 Salt Input) Header Parameter}
   */
  readonly p2s: string;

  /**
   * PBES2 Count.
   *
   * Contains the PBKDF2 iteration count, represented as a positive JSON integer.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1.2|RFC 7518 "p2c" (PBES2 Count) Header Parameter}
   */
  readonly p2c: number;
}
