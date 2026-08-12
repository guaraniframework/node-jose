import { GeneralJsonWebSignatureTokenSignature } from './general-jsonwebsignature-token-signature';

/**
 * General JSON Web Signature Token.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1|RFC 7515 General JWS JSON Serialization Syntax}
 */
export interface GeneralJsonWebSignatureToken {
  /**
   * JSON Web Signature Payload.
   */
  readonly payload?: string;

  /**
   * JSON Web Signature Signatures.
   */
  readonly signatures: GeneralJsonWebSignatureTokenSignature[];
}
