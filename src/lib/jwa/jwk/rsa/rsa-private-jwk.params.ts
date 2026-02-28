import { RsaPublicJwkParams } from './rsa-public-jwk.params';

/**
 * RSA Private JWK Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2|RFC 7518 Parameters for RSA Private Keys}
 */
export interface RsaPrivateJwkParams extends RsaPublicJwkParams {
  /**
   * JWK Private Exponent.
   *
   * Contains the private exponent value for the RSA private key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.1|RFC 7518 "d" parameter}
   */
  readonly d: string;

  /**
   * JWK First Prime Factor.
   *
   * Contains the first prime factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.2|RFC 7518 "p" parameter}
   */
  readonly p: string;

  /**
   * JWK Second Prime Factor.
   *
   * Contains the second prime factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.3|RFC 7518 "q" parameter}
   */
  readonly q: string;

  /**
   * JWK First Factor CRT Exponent.
   *
   * Contains the Chinese Remainder Theorem (CRT) exponent of the first factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.4|RFC 7518 "dp" parameter}
   */
  readonly dp: string;

  /**
   * JWK Second Factor CRT Exponent.
   *
   * Contains the Chinese Remainder Theorem (CRT) exponent of the second factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.5|RFC 7518 "dq" parameter}
   */
  readonly dq: string;

  /**
   * JWK First CRT Coefficient.
   *
   * Contains contains the Chinese Remainder Theorem (CRT) coefficient of the second factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.6|RFC 7518 "qi" parameter}
   */
  readonly qi: string;
}
