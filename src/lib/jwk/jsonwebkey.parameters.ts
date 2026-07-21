import { JoseAlgorithm } from '../jwa/jose/jose-algorithm.type';
import { KeyOperation } from '../jwa/jwk/key-operation.type';
import { KeyType } from '../jwa/jwk/key-type.type';
import { PublicKeyUse } from '../jwa/jwk/public-key-use.type';

/**
 * JSON Web Key Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4|RFC 7517 JSON Web Key (JWK) Format}
 */
export interface JsonWebKeyParameters extends Record<string, unknown> {
  /**
   * Key Type.
   *
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" (Key Type) Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" (Key Type) Parameter Values}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2|RFC 8037 Key Type "OKP"}
   */
  readonly kty: KeyType;

  /**
   * Public Key Use.
   *
   * Identifies the intended use of the public key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.2|RFC 7517 "use" (Public Key Use) Parameter}
   */
  use?: PublicKeyUse;

  /**
   * Key Operations.
   *
   * Identifies the operation(s) for which the key is intended to be used.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3|RFC 7517 "key_ops" (Key Operations) Parameter}
   */
  key_ops?: KeyOperation[];

  /**
   * JOSE Algorithm.
   *
   * Identifies the algorithm intended for use with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" (Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1|RFC 7516 "alg" (Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.4|RFC 7517 "alg" (Algorithm) Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWS}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWE}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1|RFC 8037 Signatures}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2|RFC 8037 ECDH-ES}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8812.html#section-3.2|RFC 8812 ECDSA Signature with secp256k1 Curve}
   */
  alg?: JoseAlgorithm;

  /**
   * Key Identifier.
   *
   * Used to match a specific key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.5|RFC 7517 "kid" (Key ID) Parameter}
   */
  kid?: string;

  /**
   * X.509 URL.
   *
   * URI that refers to a resource for an X.509 public key certificate or certificate chain.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.6|RFC 7517 "x5u" (X.509 URL) Parameter}
   */
  x5u?: string;

  /**
   * X.509 Certificate Chain.
   *
   * Contains a chain of one or more PKIX certificates.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.7|RFC 7517 "x5c" (X.509 Certificate Chain) Parameter}
   */
  x5c?: string[];

  /**
   * X.509 Certificate SHA-1 Thumbprint.
   *
   * Base64url-encoded SHA-1 thumbprint of the DER encoding of an X.509 certificate.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.8|RFC 7517 "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter}
   */
  x5t?: string;

  /**
   * X.509 Certificate SHA-256 Thumbprint.
   *
   * Base64url-encoded SHA-256 thumbprint of the DER encoding of an X.509 certificate.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.9|RFC 7517 "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter}
   */
  'x5t#S256'?: string;
}
