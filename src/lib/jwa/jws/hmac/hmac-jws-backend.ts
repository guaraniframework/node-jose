import { Buffer } from 'buffer';
import { createHmac, createSecretKey, timingSafeEqual } from 'crypto';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { InvalidJwsException } from '../../../exceptions/invalid-jws.exception';
import { JwkKty } from '../../jwk/jwk-kty.type';
import { OctJwk } from '../../jwk/oct/oct-jwk';
import { JwsAlg } from '../jws-alg.type';
import { JwsBackend } from '../jws-backend';

/**
 * Implementation of the HMAC JWS Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2|RFC 7518 HMAC with SHA-2 Functions}
 */
export class HmacJwsBackend extends JwsBackend {
  /**
   * JWK Key Type used by the JWS Backend.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" parameter}
   */
  protected readonly kty: JwkKty = 'oct';

  /**
   * Hash Algorithm used to sign and verify messages.
   */
  private readonly hash: string;

  /**
   * Size of the secret accepted by the HMAC JWS Backend.
   */
  private readonly keySize: number;

  /**
   * Key Sizes supported by the HMAC JWS Backend.
   */
  private static get supportedKeySizes(): number[] {
    return [32, 48, 64];
  }

  /**
   * Instantiates a new HMAC JWS Backend.
   *
   * @param keySize Size of the secret accepted by the HMAC JWS Backend.
   */
  public constructor(keySize: number) {
    if (!HmacJwsBackend.supportedKeySizes.includes(keySize)) {
      throw new TypeError(`Unsupported key size "${String(keySize)}".`);
    }

    const bitSize = keySize << 3;
    const alg = `HS${bitSize}` as JwsAlg;

    super(alg);

    this.hash = `SHA${bitSize}`;
    this.keySize = keySize;
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
  public async sign(message: Buffer, key: OctJwk): Promise<Buffer> {
    this.validateJwk(key);
    const cryptoKey = createSecretKey(key.k, 'base64url');
    return createHmac(this.hash, cryptoKey).update(message).digest();
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
  public async verify(signature: Buffer, message: Buffer, key: OctJwk): Promise<void> {
    this.validateJwk(key);

    const calculatedSignature = await this.sign(message, key);

    if (signature.length !== calculatedSignature.length || !timingSafeEqual(signature, calculatedSignature)) {
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
  protected override validateJwk(key: OctJwk): void {
    super.validateJwk(key);

    if (Buffer.byteLength(key.k, 'base64url') < this.keySize) {
      throw new InvalidJwkException(`The jwk parameter "k" must be at least ${this.keySize} bytes.`);
    }
  }
}
