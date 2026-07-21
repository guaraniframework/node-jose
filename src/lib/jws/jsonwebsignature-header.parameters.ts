import { JoseHeaderParameters } from '../jose/jose-header.parameters';
import { DigitalSignatureAlgorithm } from '../jwa/jws/digital-signature-algorithm.type';

/**
 * JSON Web Signature Header Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1|RFC 7515 Registered Header Parameter Names}
 */
export interface JsonWebSignatureHeaderParameters extends JoseHeaderParameters {
  /**
   * JSON Web Signature Algorithm.
   *
   * Cryptographic algorithm used to secure the JWS.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" (Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWS}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1|RFC 8037 Signatures}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8812.html#section-3.2|RFC 8812 ECDSA Signature with secp256k1 Curve}
   */
  readonly alg: DigitalSignatureAlgorithm;

  /**
   * Base64Url Encoded Payload.
   *
   * Determines whether the payload is represented in the JWS and the JWS Signing Input
   * as ASCII(BASE64URL(JWS Payload)) or as the JWS Payload value itself with no encoding performed.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7797.html#section-3|RFC 7797 The "b64" Header Parameter}
   */
  b64?: boolean;
}
