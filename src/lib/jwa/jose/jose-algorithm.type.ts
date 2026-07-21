import { KeyManagementAlgorithm } from '../jwe/alg/key-management-algorithm.type';
import { DigitalSignatureAlgorithm } from '../jws/digital-signature-algorithm.type';

/**
 * Cryptographic Algorithms for Digital Signatures, MACs and Key Management.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" (Algorithm) Header Parameter}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1|RFC 7516 "alg" (Algorithm) Header Parameter}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWS}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWE}
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1|RFC 8037 Signatures}
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2|RFC 8037 ECDH-ES}
 * @see {@link https://www.rfc-editor.org/rfc/rfc8812.html#section-3.2|RFC 8812 ECDSA Signature with secp256k1 Curve}
 */
export type JoseAlgorithm = DigitalSignatureAlgorithm | KeyManagementAlgorithm;
