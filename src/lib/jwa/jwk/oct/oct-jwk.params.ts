import { JwkParams } from '../../../jwk/jwk.params';

/**
 * Octet Sequence JWK Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4|RFC 7518 Parameters for Symmetric Keys}
 */
export interface OctJwkParams extends JwkParams {
  /**
   * JWK Key Type.
   *
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4|RFC 7518 "kty" parameter}
   */
  readonly kty: 'oct';

  /**
   * JWK Key Value.
   *
   * Contains the value of the symmetric key.
   * It is represented as the base64url encoding of the octet sequence containing the key value.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4.1|RFC 7518 "k" parameter}
   */
  readonly k: string;
}
