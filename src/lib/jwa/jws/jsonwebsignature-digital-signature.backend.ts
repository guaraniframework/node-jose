import { Buffer } from 'buffer';

import { JsonWebKey } from '../../jwk/jsonwebkey';
import { DigitalSignatureAlgorithm } from './digital-signature-algorithm.type';

/**
 * Implementation of the JSON Web Signature Digital Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3|RFC 7518 Cryptographic Algorithms for Digital Signatures and MACs}
 */
export abstract class JsonWebSignatureDigitalSignatureBackend {
  /**
   * JSON Web Signature Digital Signature Algorithm.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" (Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWS}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1|RFC 8037 Signatures}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8812.html#section-3.2|RFC 8812 ECDSA Signature with secp256k1 Curve}
   */
  protected readonly algorithm: DigitalSignatureAlgorithm;

  /**
   * Instantiates a new JSON Web Signature Digital Signature Backend.
   *
   * @param algorithm JSON Web Signature Digital Signature Algorithm.
   */
  public constructor(algorithm: DigitalSignatureAlgorithm) {
    this.algorithm = algorithm;
  }

  /**
   * Signs a Message using the provided JSON Web Key.
   *
   * @param message Message to be signed.
   * @param jwk JSON Web Key used to sign the Message.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the JSON Web Signature Digital Signature Algorithm.
   * @returns Signature of the Message.
   */
  public abstract sign(message: Buffer, jwk: JsonWebKey | null): Promise<Buffer>;

  /**
   * Checks if the provided Signature and Message match based on the provided JSON Web Key.
   *
   * @param signature Signature to be verified.
   * @param message Message to be matched against the Signature.
   * @param jwk JSON Web Key used to verify the Signature.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the JSON Web Signature Digital Signature Algorithm.
   * @throws {InvalidJsonWebSignatureError} Failed to verify the provided JSON Web Signature.
   */
  public abstract verify(signature: Buffer, message: Buffer, jwk: JsonWebKey | null): Promise<void>;
}
