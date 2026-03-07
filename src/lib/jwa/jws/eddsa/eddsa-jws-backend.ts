import { Buffer } from 'buffer';
import { sign, verify } from 'crypto';
import { promisify } from 'util';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { InvalidJwsException } from '../../../exceptions/invalid-jws.exception';
import { JwkCrv } from '../../jwk/jwk-crv.type';
import { JwkKty } from '../../jwk/jwk-kty.type';
import { OkpPrivateJwk } from '../../jwk/okp/okp-private-jwk';
import { OkpPublicJwk } from '../../jwk/okp/okp-public-jwk';
import { JwsBackend } from '../jws-backend';

const signAsync = promisify(sign);
const verifyAsync = promisify(verify);

/**
 * Implementation of the EdDSA JWS Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1|RFC 8037 EdDSA Signatures}
 */
export class EddsaJwsBackend extends JwsBackend {
  /**
   * JWK Key Type used by the JWS Backend.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" parameter}
   */
  protected readonly kty: JwkKty = 'OKP';

  /**
   * Elliptic Curves supported by the EdDSA JWS Backend.
   */
  private static supportedEllipticCurves: Extract<JwkCrv, 'Ed25519' | 'Ed448'>[] = ['Ed25519', 'Ed448'];

  /**
   * Instantiates a new ECDSA JWS Backend.
   *
   * @param curve Elliptic Curve accepted by the ECDSA JWS Backend.
   */
  public constructor() {
    super('EdDSA');
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
  public async sign(message: Buffer, key: OkpPrivateJwk): Promise<Buffer> {
    this.validateJwk(key);
    return await signAsync(null, message, key.cryptoKey);
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
  public async verify(signature: Buffer, message: Buffer, key: OkpPublicJwk): Promise<void> {
    this.validateJwk(key);

    if (!(await verifyAsync(null, message, key.cryptoKey, signature))) {
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
  protected override validateJwk(key: OkpPublicJwk | OkpPrivateJwk): void {
    super.validateJwk(key);

    if (!EddsaJwsBackend.supportedEllipticCurves.includes(<Extract<JwkCrv, 'Ed25519' | 'Ed448'>>key.crv)) {
      throw new InvalidJwkException(
        `The jwk parameter "crv" must be one of ["${EddsaJwsBackend.supportedEllipticCurves.join('", "')}"].`,
      );
    }
  }
}
