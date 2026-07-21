/**
 * JSON Web Token Claims Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1|RFC 7519 Registered Claim Names}
 */
export interface JsonWebTokenClaimsParameters extends Record<string, unknown> {
  /**
   * Issuer.
   *
   * Principal that issued the JWT.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.1|RFC 7519 "iss" (Issuer) Claim}
   */
  readonly iss?: string;

  /**
   * Subject.
   *
   * Principal that is the subject of the JWT.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2|RFC 7519 "sub" (Subject) Claim}
   */
  readonly sub?: string;

  /**
   * Audience.
   *
   * Recipients that the JWT is intended for.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3|RFC 7519 "aud" (Audience) Claim}
   */
  readonly aud?: string | string[];

  /**
   * Expiration Time.
   *
   * Expiration time on or after which the JWT MUST NOT be accepted for processing.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4|RFC 7519 "exp" (Expiration Time) Claim}
   */
  readonly exp?: number;

  /**
   * Not Before.
   *
   * Time before which the JWT MUST NOT be accepted for processing.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.5|RFC 7519 "nbf" (Not Before) Claim}
   */
  readonly nbf?: number;

  /**
   * Issued At.
   *
   * Time at which the JWT was issued.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6|RFC 7519 "iat" (Issued At) Claim}
   */
  readonly iat?: number;

  /**
   * JWT ID.
   *
   * Provides a unique identifier for the JWT.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7|RFC 7519 "jti" (JWT ID) Claim}
   */
  readonly jti?: string;
}
