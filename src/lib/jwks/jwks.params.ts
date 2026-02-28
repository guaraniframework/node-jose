import { JwkParams } from '../jwk/jwk.params';

/**
 * JWK Set Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-5|RFC 7517 JSON Web Key Set Format}
 */
export interface JwksParams {
  /**
   * JWK Set Keys Parameter.
   *
   * Array of JWK values.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-5.1|RFC 7517 "keys" parameter}
   */
  readonly keys: JwkParams[];
}
