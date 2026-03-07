import { Buffer } from 'buffer';
import { constants, sign, verify } from 'crypto';
import { promisify } from 'util';

import { InvalidJwsException } from '../../../exceptions/invalid-jws.exception';
import { JwkKty } from '../../jwk/jwk-kty.type';
import { RsaPrivateJwk } from '../../jwk/rsa/rsa-private-jwk';
import { RsaPublicJwk } from '../../jwk/rsa/rsa-public-jwk';
import { JwsAlg } from '../jws-alg.type';
import { JwsBackend } from '../jws-backend';

const signAsync = promisify(sign);
const verifyAsync = promisify(verify);

type RsaSsaPadding = 'RSASSA-PKCS1-v1_5' | 'RSASSA-PSS';

/**
 * Implementation of the ECDSA JWS Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3|RFC 7518 Digital Signature with RSASSA-PKCS1-v1_5}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5|RFC 7518 Digital Signature with RSASSA-PSS}
 */
export class RsaSsaJwsBackend extends JwsBackend {
  /**
   * JWK Key Type used by the JWS Backend.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" parameter}
   */
  protected readonly kty: JwkKty = 'RSA';

  /**
   * Hash Algorithm used to sign and verify messages.
   */
  private readonly hash: string;

  /**
   * RSASSA Padding used by the RSASSA JWS Backend to sign and verify messages.
   */
  private readonly padding: number;

  /**
   * Hashes supported by the RSASSA JWS Backend.
   */
  private static supportedHashes: string[] = ['SHA256', 'SHA384', 'SHA512'];

  /**
   * RSASSA Paddings supported by the RSASSA JWS Backend.
   */
  private static supportedRsaSsaPaddings: RsaSsaPadding[] = ['RSASSA-PKCS1-v1_5', 'RSASSA-PSS'];

  /**
   * Mapping of Elliptic Curves to their respective bitsizes.
   */
  private static rsaSsaPaddingsNames: Record<RsaSsaPadding, number> = {
    'RSASSA-PKCS1-v1_5': constants.RSA_PKCS1_PADDING,
    'RSASSA-PSS': constants.RSA_PKCS1_PSS_PADDING,
  };

  /**
   * Instantiates a new RSASSA JWS Backend.
   *
   * @param hash Hash Algorithm used to sign and verify messages.
   * @param rsaSsaPadding RSASSA Padding accepted by the RSASSA JWS Backend.
   */
  public constructor(hash: string, rsaSsaPadding: RsaSsaPadding) {
    if (!RsaSsaJwsBackend.supportedHashes.includes(hash)) {
      throw new TypeError(`Unsupported hash "${String(hash)}".`);
    }

    if (!RsaSsaJwsBackend.supportedRsaSsaPaddings.includes(rsaSsaPadding)) {
      throw new TypeError(`Unsupported rsassa padding "${String(rsaSsaPadding)}".`);
    }

    super(`${rsaSsaPadding === 'RSASSA-PKCS1-v1_5' ? 'R' : 'P'}S${hash.substring(2)}` as JwsAlg);

    this.hash = hash;
    this.padding = RsaSsaJwsBackend.rsaSsaPaddingsNames[rsaSsaPadding];
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
  public async sign(message: Buffer, key: RsaPrivateJwk): Promise<Buffer> {
    this.validateJwk(key);
    return await signAsync(this.hash, message, { key: key.cryptoKey, padding: this.padding });
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
  public async verify(signature: Buffer, message: Buffer, key: RsaPublicJwk): Promise<void> {
    this.validateJwk(key);

    if (!(await verifyAsync(this.hash, message, { key: key.cryptoKey, padding: this.padding }, signature))) {
      throw new InvalidJwsException('Signature verification failed.');
    }
  }
}
