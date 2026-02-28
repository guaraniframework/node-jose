import { JweAlg } from '../jwa/jwe/jwe-alg.type';
import { JwkKeyOp } from '../jwa/jwk/jwk-key-op.type';
import { JwkKty } from '../jwa/jwk/jwk-kty.type';
import { JwkUse } from '../jwa/jwk/jwk-use.type';
import { JwsAlg } from '../jwa/jws/jws-alg.type';

/**
 * Base JWK Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4|RFC 7517 JSON Web Key Format}
 */
export interface JwkParams extends Record<string, unknown> {
  /**
   * JWK Key Type.
   *
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" parameter}
   */
  readonly kty: JwkKty;

  /**
   * JWK Public Key Use.
   *
   * Identifies the intended use of the public key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.2|RFC 7517 "use" parameter}
   */
  use?: JwkUse;

  /**
   * JWK Key Operations.
   *
   * Identifies the operation(s) for which the key is intended to be used.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3|RFC 7517 "key_ops" parameter}
   */
  key_ops?: JwkKeyOp[];

  /**
   * JWK Algorithm.
   *
   * Identifies the algorithm intended for use with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.4|RFC 7517 "alg" parameter}
   */
  alg?: JwsAlg | JweAlg;

  /**
   * JWK Key ID.
   *
   * Used to match a specific key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.5|RFC 7517 "kid" parameter}
   */
  kid?: string;

  /**
   * JWK X.509 URL.
   *
   * URI that refers to a resource for an X.509 public key certificate or certificate chain.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.6|RFC 7517 "x5u" parameter}
   */
  x5u?: string;

  /**
   * JWK X.509 Certificate Chain.
   *
   * Contains a chain of one or more PKIX certificates.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.7|RFC 7517 "x5c" parameter}
   */
  x5c?: string[];

  /**
   * JWK X.509 Certificate SHA-1 Thumbprint.
   *
   * Base64url-encoded SHA-1 thumbprint of the DER encoding of an X.509 certificate.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.8|RFC 7517 "x5t" parameter}
   */
  x5t?: string;

  /**
   * JWK X.509 Certificate SHA-256 Thumbprint.
   *
   * Base64url-encoded SHA-256 thumbprint of the DER encoding of an X.509 certificate.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.9|RFC 7517 "x5t#S256" parameter}
   */
  'x5t#S256'?: string;
}
