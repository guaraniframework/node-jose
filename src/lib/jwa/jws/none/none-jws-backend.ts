import { Buffer } from 'buffer';

import { InvalidJwsException } from '../../../exceptions/invalid-jws.exception';
import { JwkKty } from '../../jwk/jwk-kty.type';
import { JwsBackend } from '../jws-backend';

/**
 * Implementation of the none JWS Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6|RFC 7518 None Algorithm}
 */
export class NoneJwsBackend extends JwsBackend {
  /**
   * JWK Key Type used by the JWS Backend.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" parameter}
   */
  protected readonly kty: JwkKty = null!;

  /**
   * Instantiates a new none JWS Backend.
   */
  public constructor() {
    super('none');
  }

  /**
   * Signs a message with the provided JWK.
   *
   * @param message Message to be signed.
   * @param key ~JWK used to sign the provided message.~
   * @returns Resulting signature of the provided message.
   */
  // @ts-expect-error Unused parameters.
  public async sign(message: Buffer, key: null): Promise<Buffer> {
    return Buffer.alloc(0);
  }

  /**
   * Checks if the provided signature matches the provided message based on the provided JWK.
   *
   * @param signature Signature to be matched against the provided message.
   * @param message Message to be matched against the provided signature.
   * @param key ~JWK used to verify the signature and message.~
   * @throws {InvalidJwsException} Signature verification failed.
   */
  // @ts-expect-error Unused parameters.
  public async verify(signature: Buffer, message: Buffer, key: null): Promise<void> {
    if (signature.byteLength !== 0) {
      throw new InvalidJwsException('The jws algorithm "none" must be used with an empty signature.');
    }
  }
}
