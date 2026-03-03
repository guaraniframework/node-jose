import { JweAlg } from '../jwa/jwe/jwe-alg.type';
import { JwsAlg } from '../jwa/jws/jws-alg.type';
import { JwkParams } from '../jwk/jwk.params';

/**
 * Base Jose Header Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4|RFC 7515 JOSE Header}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4|RFC 7516 JOSE Header}
 */
export interface JoseHeaderParams extends Record<string, unknown> {
  /**
   * JOSE Header Algorithm.
   *
   * Identifies the cryptographic algorithm used to secure the JWS,
   * or to encrypt or determine the value of the CEK.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1|RFC 7516 "alg" parameter}
   */
  readonly alg: JwsAlg | JweAlg;

  /**
   * JOSE Header JWK Set URL.
   *
   * URI that refers to a resource for a set of JSON-encoded public keys,
   * one of which corresponds to the key used to digitally sign the JWS,
   * or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.2|RFC 7515 "jku" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.4|RFC 7516 "jku" parameter}
   */
  readonly jku?: string;

  /**
   * JOSE Header JSON Web Key.
   *
   * Public key that corresponds to the key used to digitally sign the JWS,
   * or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.3|RFC 7515 "jwk" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.5|RFC 7516 "jwk" parameter}
   */
  readonly jwk?: JwkParams;

  /**
   * JOSE Header Key ID.
   *
   * Hint indicating which key was used to secure the JWS, or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.4|RFC 7515 "kid" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.6|RFC 7516 "kid" parameter}
   */
  readonly kid?: string;

  /**
   * JOSE Header X.509 URL.
   *
   * URI that refers to a resource for the X.509 public key certificate
   * or certificate chain corresponding to the key used to digitally sign the JWS,
   * or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.5|RFC 7515 "x5u" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.7|RFC 7516 "x5u" parameter}
   */
  readonly x5u?: string;

  /**
   * JOSE Header X.509 Certificate Chain.
   *
   * X.509 public key certificate or certificate chain corresponding
   * to the key used to digitally sign the JWS, or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6|RFC 7515 "x5c" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.8|RFC 7516 "x5c" parameter}
   */
  readonly x5c?: string[];

  /**
   * JOSE Header X.509 Certificate SHA-1 Thumbprint.
   *
   * Base64url-encoded SHA-1 thumbprint of the DER encoding of the X.509 certificate
   * corresponding to the key used to digitally sign the JWS, or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.7|RFC 7515 "x5t" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.9|RFC 7516 "x5t" parameter}
   */
  readonly x5t?: string;

  /**
   * JOSE Header X.509 Certificate SHA-256 Thumbprint.
   *
   * Base64url-encoded SHA-256 thumbprint of the DER encoding of the X.509 certificate
   * corresponding to the key used to digitally sign the JWS, or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.8|RFC 7515 "x5t#S256" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.10|RFC 7516 "x5t#S256" parameter}
   */
  readonly 'x5t#S256'?: string;

  /**
   * JOSE Header Type.
   *
   * Used by JWS applications to declare the media type of this complete JWS or JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.9|RFC 7515 "typ" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.11|RFC 7516 "typ" parameter}
   */
  readonly typ?: string;

  /**
   * JOSE Header Content Type.
   *
   * Used by JWS applications to declare the media type of the secured content (payload/plaintext).
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10|RFC 7515 "cty" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.12|RFC 7516 "cty" parameter}
   */
  readonly cty?: string;

  /**
   * JOSE Header Critical.
   *
   * Indicates that extensions to this specification and/or JWA are being used
   * that MUST be understood and processed.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11|RFC 7515 "crit" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.13|RFC 7516 "crit" parameter}
   */
  readonly crit?: string[];
}
