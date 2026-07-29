import { Buffer } from 'buffer';
import { constants, sign, verify } from 'crypto';
import { promisify } from 'util';

import { InvalidJsonWebKeyError } from '../../../errors/invalid-jsonwebkey.error';
import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { RsaJsonWebKey } from '../../jwk/rsa/rsa.jsonwebkey';
import { DigitalSignatureAlgorithm } from '../digital-signature-algorithm.type';
import { JsonWebSignatureDigitalSignatureBackend } from '../jsonwebsignature-digital-signature.backend';

const signAsync = promisify(sign);
const verifyAsync = promisify(verify);

/**
 * Implementation of the RSASSA JSON Web Signature Digital Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3|RFC 7518 Digital Signature with RSASSA-PKCS1-v1_5}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5|RFC 7518 Digital Signature with RSASSA-PSS}
 */
export class RSASSAJsonWebSignatureDigitalSignatureBackend extends JsonWebSignatureDigitalSignatureBackend {
  /**
   * Hash Algorithm.
   */
  private readonly hash: string;

  /**
   * RSA Padding.
   */
  private readonly padding: number;

  /**
   * Instantiates a new RSASSA JSON Web Signature Digital Signature Backend.
   *
   * @param algorithm JSON Web Signature Digital Signature Algorithm.
   */
  public constructor(
    algorithm: Extract<DigitalSignatureAlgorithm, 'PS256' | 'PS384' | 'PS512' | 'RS256' | 'RS384' | 'RS512'>,
  ) {
    super(algorithm);

    const bitSize = Number.parseInt(algorithm.substring(2));

    this.hash = `sha-${bitSize}`;
    this.padding = algorithm.startsWith('P') ? constants.RSA_PKCS1_PSS_PADDING : constants.RSA_PKCS1_PADDING;
  }

  /**
   * Signs a Message using the provided JSON Web Key.
   *
   * @param message Message to be signed.
   * @param jwk JSON Web Key used to sign the Message.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the JSON Web Signature Digital Signature Algorithm.
   * @returns Signature of the Message.
   */
  public async sign(message: Buffer, jwk: RsaJsonWebKey): Promise<Buffer> {
    this.validateJsonWebKey(jwk);

    if (jwk.cryptoKey.type !== 'private') {
      throw new InvalidJsonWebKeyError('The provided JSON Web Key cannot be used to sign a Message.');
    }

    return await signAsync(this.hash, message, { key: jwk.cryptoKey, padding: this.padding });
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
  public async verify(signature: Buffer, message: Buffer, jwk: RsaJsonWebKey): Promise<void> {
    this.validateJsonWebKey(jwk);

    const result = await verifyAsync(this.hash, message, { key: jwk.cryptoKey, padding: this.padding }, signature);

    if (!result) {
      throw new InvalidJsonWebSignatureError('The provided JSON Web Signature is invalid.');
    }
  }

  /**
   * Checks if the provided JSON Web Key can be used.
   *
   * @param jwk JSON Web Key to be checked.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the JSON Web Signature Digital Signature Algorithm.
   */
  private validateJsonWebKey(jwk: RsaJsonWebKey): void {
    if (!(jwk instanceof JsonWebKey) || ('alg' in jwk.parameters && jwk.parameters.alg !== this.algorithm)) {
      throw new InvalidJsonWebKeyError('The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.');
    }

    if (jwk.parameters.kty !== 'RSA') {
      throw new InvalidJsonWebKeyError('The JSON Web Signature Algorithm only accepts "RSA" JSON Web Keys.');
    }
  }
}
