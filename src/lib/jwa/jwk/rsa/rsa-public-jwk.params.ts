import { JwkParams } from '../../../jwk/jwk.params';

/**
 * RSA Public JWK Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1|RFC 7518 Parameters for RSA Public Keys}
 */
export interface RsaPublicJwkParams extends JwkParams {
  /**
   * JWK Key Type.
   *
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3|RFC 7518 "kty" parameter}
   */
  readonly kty: 'RSA';

  /**
   * JWK Modulus.
   *
   * Contains the modulus value for the RSA public key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1.1|RFC 7518 "n" parameter}
   */
  readonly n: string;

  /**
   * JWK Exponent.
   *
   * Contains the exponent value for the RSA public key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1.2|RFC 7518 "e" parameter}
   */
  readonly e: string;
}
