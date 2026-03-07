import { Buffer } from 'buffer';

import { InvalidJwkException } from '../../exceptions/invalid-jwk.exception';
import { Jwk } from '../../jwk/jwk';
import { JwkKty } from '../jwk/jwk-kty.type';
import { JwsAlg } from './jws-alg.type';

/**
 * JWS Backend Base Class.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3|RFC 7518 Cryptographic Algorithms for Digital Signatures and MACs}
 */
export abstract class JwsBackend {
  /**
   * JWK Key Type used by the JWS Backend.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" parameter}
   */
  protected abstract readonly kty: JwkKty;

  /**
   * Name of the JWS Algorithm used by the JWS Backend.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1|RFC 7518 "alg" parameter}
   */
  protected readonly alg: JwsAlg;

  /**
   * Instantiates a new JWS Backend.
   *
   * @param alg JWS Algorithm.
   */
  public constructor(alg: JwsAlg) {
    this.alg = alg;
  }

  /**
   * Signs a message with the provided JWK.
   *
   * @param message Message to be signed.
   * @param key JWK used to sign the provided message.
   * @returns Resulting signature of the provided message.
   */
  public abstract sign(message: Buffer, key: Jwk | null): Promise<Buffer>;

  /**
   * Checks if the provided signature matches the provided message based on the provided JWK.
   *
   * @param signature Signature to be matched against the provided message.
   * @param message Message to be matched against the provided signature.
   * @param key JWK used to verify the signature and message.
   * @throws {InvalidJwsException} Signature verification failed.
   */
  public abstract verify(signature: Buffer, message: Buffer, key: Jwk | null): Promise<void>;

  /**
   * Checks if the provided JWK can be used by the requesting JWS Backend.
   *
   * @param key JWK to be checked.
   * @throws {TypeError} The provided key is not a valid JWK.
   * @throws {InvalidJwkException} The provided JWK is invalid.
   */
  protected validateJwk(key: Jwk): void {
    if (!(key instanceof Jwk)) {
      throw new TypeError('Invalid jwk.');
    }

    if (key.kty !== this.kty) {
      throw new InvalidJwkException(`The jws algorithm "${this.alg}" only accepts "${this.kty}" jwk keys.`);
    }

    if (typeof key.alg !== 'undefined' && key.alg !== this.alg) {
      throw new InvalidJwkException(`This jwk is intended to be used by the jws algorithm "${this.alg}".`);
    }
  }
}
