import { Buffer } from 'buffer';
import { sign, verify } from 'crypto';
import { promisify } from 'util';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { InvalidJwsException } from '../../../exceptions/invalid-jws.exception';
import { EcPrivateJwk } from '../../jwk/ec/ec-private-jwk';
import { EcPublicJwk } from '../../jwk/ec/ec-public-jwk';
import { JwkCrv } from '../../jwk/jwk-crv.type';
import { JwkKty } from '../../jwk/jwk-kty.type';
import { JwsAlg } from '../jws-alg.type';
import { JwsBackend } from '../jws-backend';

const signAsync = promisify(sign);
const verifyAsync = promisify(verify);

/**
 * Implementation of the ECDSA JWS Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4|RFC 7518 Digital Signature with ECDSA}
 */
export class EcdsaJwsBackend extends JwsBackend {
  /**
   * JWK Key Type used by the JWS Backend.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" parameter}
   */
  protected readonly kty: JwkKty = 'EC';

  /**
   * Hash Algorithm used to sign and verify messages.
   */
  private readonly hash: string;

  /**
   * Size of the secret accepted by the ECDSA JWS Backend.
   */
  private readonly curve: Extract<JwkCrv, 'P-256' | 'P-384' | 'P-521'>;

  /**
   * Elliptic Curves supported by the ECDSA JWS Backend.
   */
  private static supportedEllipticCurves: Extract<JwkCrv, 'P-256' | 'P-384' | 'P-521'>[] = ['P-256', 'P-384', 'P-521'];

  /**
   * Mapping of Elliptic Curves to their respective bitsizes.
   */
  private static curvesBitSizes: Record<Extract<JwkCrv, 'P-256' | 'P-384' | 'P-521'>, number> = {
    'P-256': 256,
    'P-384': 384,
    'P-521': 512,
  };

  /**
   * Instantiates a new ECDSA JWS Backend.
   *
   * @param curve Elliptic Curve accepted by the ECDSA JWS Backend.
   */
  public constructor(curve: Extract<JwkCrv, 'P-256' | 'P-384' | 'P-521'>) {
    if (!EcdsaJwsBackend.supportedEllipticCurves.includes(curve)) {
      throw new TypeError(`Unsupported elliptic curve "${String(curve)}".`);
    }

    const bitSize = EcdsaJwsBackend.curvesBitSizes[curve];
    const alg = `ES${bitSize}` as JwsAlg;

    super(alg);

    this.hash = `SHA${bitSize}`;
    this.curve = curve;
  }

  /**
   * Signs a message with the provided JWK.
   *
   * @param message Message to be signed.
   * @param key JWK used to sign the provided message.
   * @returns Resulting signature of the provided message.
   * @throws {TypeError} The provided key is not a valid JWK.
   * @throws {InvalidJwkException} The provided JWK is invalid.
   */
  public async sign(message: Buffer, key: EcPrivateJwk): Promise<Buffer> {
    this.validateJwk(key);
    return await signAsync(this.hash, message, key.cryptoKey);
  }

  /**
   * Checks if the provided signature matches the provided message based on the provided JWK.
   *
   * @param signature Signature to be matched against the provided message.
   * @param message Message to be matched against the provided signature.
   * @param key JWK used to verify the signature and message.
   * @throws {TypeError} The provided key is not a valid JWK.
   * @throws {InvalidJwkException} The provided JWK is invalid.
   * @throws {InvalidJwsException} Signature verification failed.
   */
  public async verify(signature: Buffer, message: Buffer, key: EcPublicJwk): Promise<void> {
    this.validateJwk(key);

    if (!(await verifyAsync(this.hash, message, key.cryptoKey, signature))) {
      throw new InvalidJwsException('Signature verification failed.');
    }
  }

  /**
   * Checks if the provided JWK can be used by the requesting JWS Backend.
   *
   * @param key JWK to be checked.
   * @throws {TypeError} The provided key is not a valid JWK.
   * @throws {InvalidJwkException} The provided JWK is invalid.
   */
  protected override validateJwk(key: EcPublicJwk | EcPrivateJwk): void {
    super.validateJwk(key);

    if (key.crv !== this.curve) {
      throw new InvalidJwkException(`The jwk parameter "crv" must be "${this.curve}".`);
    }
  }
}
