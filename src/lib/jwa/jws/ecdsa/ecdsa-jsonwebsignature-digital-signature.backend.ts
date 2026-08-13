import { Buffer } from 'buffer';
import { sign, verify } from 'crypto';
import { promisify } from 'util';

import { InvalidJsonWebKeyError } from '../../../errors/invalid-jsonwebkey.error';
import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { EllipticCurveJsonWebKey } from '../../jwk/ec/elliptic-curve.jsonwebkey';
import { EllipticCurve } from '../../jwk/ec/elliptic-curve.type';
import { DigitalSignatureAlgorithm } from '../digital-signature-algorithm.type';
import { JsonWebSignatureDigitalSignatureBackend } from '../jsonwebsignature-digital-signature.backend';

const signAsync = promisify(sign);
const verifyAsync = promisify(verify);

/**
 * Implementation of the ECDSA JSON Web Signature Digital Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4|RFC 7518 Digital Signature with ECDSA}
 */
export class ECDSAJsonWebSignatureDigitalSignatureBackend extends JsonWebSignatureDigitalSignatureBackend {
  /**
   * Mapping of the JSON Web Signature Digital Signature Algorithms to the respective Elliptic Curves.
   */
  static readonly #algorithmCurveMap: Record<
    Extract<DigitalSignatureAlgorithm, 'ES256' | 'ES256K' | 'ES384' | 'ES512'>,
    EllipticCurve
  > = {
    ES256: 'P-256',
    ES256K: 'secp256k1',
    ES384: 'P-384',
    ES512: 'P-521',
  };

  /**
   * Hash Algorithm.
   */
  private readonly hash: string;

  /**
   * Elliptic Curve.
   */
  private readonly curve: EllipticCurve;

  /**
   * Instantiates a new ECDSA JSON Web Signature Digital Signature Backend.
   *
   * @param algorithm JSON Web Signature Digital Signature Algorithm.
   */
  public constructor(algorithm: Extract<DigitalSignatureAlgorithm, 'ES256' | 'ES256K' | 'ES384' | 'ES512'>) {
    super(algorithm);

    const bitSize = Number.parseInt(algorithm.substring(2, 5));

    this.hash = `sha-${bitSize}`;
    this.curve = ECDSAJsonWebSignatureDigitalSignatureBackend.#algorithmCurveMap[algorithm];
  }

  /**
   * Signs a Message using the provided JSON Web Key.
   *
   * @param message Message to be signed.
   * @param jsonWebKey JSON Web Key used to sign the Message.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the JSON Web Signature Digital Signature Algorithm.
   * @returns Signature of the Message.
   */
  public async sign(message: Buffer, jsonWebKey: EllipticCurveJsonWebKey): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);

    if (jsonWebKey.cryptoKey.type !== 'private') {
      throw new InvalidJsonWebKeyError('The provided JSON Web Key cannot be used to sign a Message.');
    }

    return await signAsync(this.hash, message, jsonWebKey.cryptoKey);
  }

  /**
   * Checks if the provided Signature and Message match based on the provided JSON Web Key.
   *
   * @param signature Signature to be verified.
   * @param message Message to be matched against the Signature.
   * @param jsonWebKey JSON Web Key used to verify the Signature.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the JSON Web Signature Digital Signature Algorithm.
   * @throws {InvalidJsonWebSignatureError} Failed to verify the provided JSON Web Signature.
   */
  public async verify(signature: Buffer, message: Buffer, jsonWebKey: EllipticCurveJsonWebKey): Promise<void> {
    this.validateJsonWebKey(jsonWebKey);

    const result = await verifyAsync(this.hash, message, jsonWebKey.cryptoKey, signature);

    if (!result) {
      throw new InvalidJsonWebSignatureError('The provided JSON Web Signature is invalid.');
    }
  }

  /**
   * Checks if the provided JSON Web Key can be used.
   *
   * @param jsonWebKey JSON Web Key to be checked.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the JSON Web Signature Digital Signature Algorithm.
   */
  private validateJsonWebKey(jsonWebKey: EllipticCurveJsonWebKey): void {
    if (
      !(jsonWebKey instanceof JsonWebKey) ||
      ('alg' in jsonWebKey.parameters && jsonWebKey.parameters.alg !== this.algorithm)
    ) {
      throw new InvalidJsonWebKeyError('The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.');
    }

    if (jsonWebKey.parameters.kty !== 'EC') {
      throw new InvalidJsonWebKeyError('The JSON Web Signature Algorithm only accepts "EC" JSON Web Keys.');
    }

    if (jsonWebKey.parameters.crv !== this.curve) {
      throw new InvalidJsonWebKeyError(`The JSON Web Key Parameter "crv" must be "${this.curve}".`);
    }
  }
}
