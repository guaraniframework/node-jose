import { Buffer } from 'buffer';
import { createHmac, timingSafeEqual } from 'crypto';

import { InvalidJsonWebKeyError } from '../../../errors/invalid-jsonwebkey.error';
import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { OctetSequenceJsonWebKey } from '../../jwk/oct/octet-sequence.jsonwebkey';
import { DigitalSignatureAlgorithm } from '../digital-signature-algorithm.type';
import { JsonWebSignatureDigitalSignatureBackend } from '../jsonwebsignature-digital-signature.backend';

/**
 * Implementation of the HMAC JSON Web Signature Digital Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2|RFC 7518 HMAC with SHA-2 Functions}
 */
export class HMACJsonWebSignatureDigitalSignatureBackend extends JsonWebSignatureDigitalSignatureBackend {
  /**
   * Hash Algorithm.
   */
  private readonly hash: string;

  /**
   * Size of the Secret in bytes.
   */
  private readonly keySize: number;

  /**
   * Instantiates a new HMAC JSON Web Signature Digital Signature Backend.
   *
   * @param algorithm JSON Web Signature Digital Signature Algorithm.
   */
  public constructor(algorithm: Extract<DigitalSignatureAlgorithm, 'HS256' | 'HS384' | 'HS512'>) {
    super(algorithm);

    const bitSize = Number.parseInt(algorithm.substring(2));

    this.hash = `sha-${bitSize}`;
    this.keySize = bitSize >> 3;
  }

  /**
   * Signs a Message using the provided JSON Web Key.
   *
   * @param message Message to be signed.
   * @param jwk JSON Web Key used to sign the Message.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the JSON Web Signature Digital Signature Algorithm.
   * @returns Signature of the Message.
   */
  public async sign(message: Buffer, jwk: OctetSequenceJsonWebKey): Promise<Buffer> {
    this.validateJsonWebKey(jwk);
    return createHmac(this.hash, jwk.cryptoKey).update(message).digest();
  }

  /**
   * Checks if the provided Signature and Message match based on the provided JSON Web Key.
   *
   * @param signature Signature to be verified.
   * @param message Message to be matched against the Signature.
   * @param jwk JSON Web Key used to verify the Signature.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the JSON Web Signature Digital Signature Algorithm.
   * @throws {InvalidJsonWebSignatureError} Failed to verify the provided JSON Web Signature.
   */
  public async verify(signature: Buffer, message: Buffer, jwk: OctetSequenceJsonWebKey): Promise<void> {
    this.validateJsonWebKey(jwk);

    const expectedSignature = await this.sign(message, jwk);

    if (signature.byteLength !== expectedSignature.byteLength || !timingSafeEqual(signature, expectedSignature)) {
      throw new InvalidJsonWebSignatureError('The provided JSON Web Signature is invalid.');
    }
  }

  /**
   * Checks if the provided JSON Web Key can be used.
   *
   * @param jwk JSON Web Key to be checked.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the JSON Web Signature Digital Signature Algorithm.
   */
  private validateJsonWebKey(jwk: OctetSequenceJsonWebKey): void {
    if (!(jwk instanceof JsonWebKey) || ('alg' in jwk.parameters && jwk.parameters.alg !== this.algorithm)) {
      throw new InvalidJsonWebKeyError('The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.');
    }

    if (jwk.parameters.kty !== 'oct') {
      throw new InvalidJsonWebKeyError('The JSON Web Signature Algorithm only accepts "oct" JSON Web Keys.');
    }

    if (Buffer.byteLength(jwk.parameters.k, 'base64url') < this.keySize) {
      throw new InvalidJsonWebKeyError(`The JSON Web Key Parameter "k" must be at least ${this.keySize} bytes.`);
    }
  }
}
