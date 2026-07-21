import { JsonWebKeyParameters } from '../../../jwk/jsonwebkey.parameters';

/**
 * RSA JSON Web Key Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3|RFC 7518 Parameters for RSA Keys}
 */
export interface RsaJsonWebKeyParameters extends JsonWebKeyParameters {
  /**
   * Key Type.
   *
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" (Key Type) Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" (Key Type) Parameter Values}
   */
  readonly kty: 'RSA';

  /**
   * Modulus.
   *
   * Contains the modulus value for the RSA public key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1.1|RFC 7518 "n" (Modulus) Parameter}
   */
  readonly n: string;

  /**
   * Exponent.
   *
   * Contains the exponent value for the RSA public key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1.2|RFC 7518 "e" (Exponent) Parameter}
   */
  readonly e: string;

  /**
   * Private Exponent.
   *
   * Contains the private exponent value for the RSA private key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.1|RFC 7518 "d" (Private Exponent) Parameter}
   */
  readonly d?: string;

  /**
   * First Prime Factor.
   *
   * Contains the first prime factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.2|RFC 7518 "p" (First Prime Factor) Parameter}
   */
  readonly p?: string;

  /**
   * Second Prime Factor.
   *
   * Contains the second prime factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.3|RFC 7518 "q" (Second Prime Factor) Parameter}
   */
  readonly q?: string;

  /**
   * First Factor CRT Exponent.
   *
   * Contains the Chinese Remainder Theorem (CRT) exponent of the first factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.4|RFC 7518 "dp" (First Factor CRT Exponent) Parameter}
   */
  readonly dp?: string;

  /**
   * Second Factor CRT Exponent.
   *
   * Contains the Chinese Remainder Theorem (CRT) exponent of the second factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.5|RFC 7518 "dq" (Second Factor CRT Exponent) Parameter}
   */
  readonly dq?: string;

  /**
   * First CRT Coefficient.
   *
   * Contains contains the Chinese Remainder Theorem (CRT) coefficient of the second factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.6|RFC 7518 "qi" (First CRT Coefficient) Parameter}
   */
  readonly qi?: string;
}
