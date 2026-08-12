import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';

/**
 * Flattened JSON Web Signature Token.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.2|RFC 7515 Flattened JWS JSON Serialization Syntax}
 */
export interface FlattenedJsonWebSignatureToken {
  /**
   * JSON Web Signature Protected Header.
   */
  readonly protected?: string;

  /**
   * JSON Web Signature Unprotected Header.
   */
  readonly header?: Partial<JsonWebSignatureHeaderParameters>;

  /**
   * JSON Web Signature Payload.
   */
  readonly payload?: string;

  /**
   * JSON Web Signature Signature.
   */
  readonly signature: string;
}
