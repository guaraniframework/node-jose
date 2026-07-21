import { JsonWebKeyParameters } from '../jwk/jsonwebkey.parameters';

/**
 * JSON Web Key Set Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-5|RFC 7517 JWK Set Format}
 */
export interface JsonWebKeySetParameters {
  /**
   * Array of JWK values.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-5.1|RFC 7517 "keys" Parameter}
   */
  readonly keys: JsonWebKeyParameters[];
}
