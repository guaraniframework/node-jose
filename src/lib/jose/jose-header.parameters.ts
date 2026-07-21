import { JoseAlgorithm } from '../jwa/jose/jose-algorithm.type';
import { JsonWebKeyParameters } from '../jwk/jsonwebkey.parameters';

/**
 * JOSE Header Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1|RFC 7515 Registered Header Parameter Names}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1|RFC 7516 Registered Header Parameter Names}
 */
export interface JoseHeaderParameters extends Record<string, unknown> {
  /**
   * JOSE Algorithm.
   *
   * Cryptographic algorithm used to secure the JWS or to encrypt or determine the value of the CEK.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" (Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1|RFC 7516 "alg" (Algorithm) Header Parameter}
   */
  readonly alg: JoseAlgorithm;

  /**
   * JWK Set URL.
   *
   * URI that refers to a resource for a set of JSON-encoded public keys,
   * one of which corresponds to the key used to digitally sign the JWS,
   * or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.2|RFC 7515 "jku" (JWK Set URL) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.4|RFC 7516 "jku" (JWK Set URL) Header Parameter}
   */
  jku?: string;

  /**
   * JSON Web Key.
   *
   * Public key that corresponds to the key used to digitally sign the JWS
   * or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.3|RFC 7515 "jwk" (JSON Web Key) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.5|RFC 7516 "jwk" (JSON Web Key) Header Parameter}
   */
  jwk?: JsonWebKeyParameters;

  /**
   * Key ID.
   *
   * Hint indicating which key was used to secure the JWS or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.4|RFC 7515 "kid" (Key ID) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.6|RFC 7516 "kid" (Key ID) Header Parameter}
   */
  kid?: string;

  /**
   * X.509 URL.
   *
   * URI that refers to a resource for the X.509 public key certificate or certificate chain
   * corresponding to the key used to digitally sign the JWS or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.5|RFC 7515 "x5u" (X.509 URL) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.7|RFC 7516 "x5u" (X.509 URL) Header Parameter}
   */
  x5u?: string;

  /**
   * X.509 Certificate Chain.
   *
   * X.509 public key certificate or certificate chain corresponding to the key
   * used to digitally sign the JWS or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6|RFC 7515 "x5c" (X.509 Certificate Chain) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.8|RFC 7516 "x5c" (X.509 Certificate Chain) Header Parameter}
   */
  x5c?: string[];

  /**
   * X.509 Certificate SHA-1 Thumbprint.
   *
   * Base64url-encoded SHA-1 thumbprint of the DER encoding of the X.509 certificate corresponding to the key
   * used to digitally sign the JWS or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.7|RFC 7515 "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.9|RFC 7516 "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter}
   */
  x5t?: string;

  /**
   * X.509 Certificate SHA-256 Thumbprint.
   *
   * Base64url-encoded SHA-256 thumbprint of the DER encoding of the X.509 certificate corresponding to the key
   * used to digitally sign the JWS or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.8|RFC 7515 "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.10|RFC 7516 "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter}
   */
  'x5t#S256'?: string;

  /**
   * Type.
   *
   * Declares the media type of this complete JWS or JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.9|RFC 7515 "typ" (Type) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.11|RFC 7516 "typ" (Type) Header Parameter}
   */
  typ?: string;

  /**
   * Content Type.
   *
   * Declares the media type of the secured content (the payload or the plaintext).
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10|RFC 7515 "cty" (Content Type) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.12|RFC 7516 "cty" (Content Type) Header Parameter}
   */
  cty?: string;

  /**
   * Critical.
   *
   * Indicates that extensions to this specification are being used that MUST be understood and processed.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11|RFC 7515 "crit" (Critical) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.13|RFC 7516 "crit" (Critical) Header Parameter}
   */
  crit?: string[];
}
