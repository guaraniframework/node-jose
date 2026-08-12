import { JsonWebSignatureHeader } from '../../jsonwebsignature-header';

/**
 * Compact JSON Web Signature.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-7.1|RFC 7515 JWS Compact Serialization}
 */
export interface CompactJsonWebSignature {
  /**
   * JSON Web Signature Payload.
   */
  readonly payload: Buffer;

  /**
   * JSON Web Signature Protected Header.
   */
  readonly protectedHeader: JsonWebSignatureHeader;
}
