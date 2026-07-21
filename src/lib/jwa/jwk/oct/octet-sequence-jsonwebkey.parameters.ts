import { JsonWebKeyParameters } from '../../../jwk/jsonwebkey.parameters';

/**
 * Octet Sequence JSON Web Key Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4|RFC 7518 Parameters for Symmetric Keys}
 */
export interface OctetSequenceJsonWebKeyParameters extends JsonWebKeyParameters {
  /**
   * Key Type.
   *
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" (Key Type) Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" (Key Type) Parameter Values}
   */
  readonly kty: 'oct';

  /**
   * Key Value.
   *
   * Contains the value of the symmetric key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4.1|RFC 7518 "k" (Key Value) Parameter}
   */
  readonly k: string;
}
