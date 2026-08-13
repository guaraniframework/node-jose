import { Buffer } from 'buffer';

import { InvalidJsonWebKeyError } from '../../../errors/invalid-jsonwebkey.error';
import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { JsonWebSignatureDigitalSignatureBackend } from '../jsonwebsignature-digital-signature.backend';

/**
 * Implementation of the none JSON Web Signature Digital Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6|RFC 7518 Using the Algorithm "none"}
 */
export class NoneJsonWebSignatureDigitalSignatureBackend extends JsonWebSignatureDigitalSignatureBackend {
  /**
   * Instantiates a new none JSON Web Signature Digital Signature Backend.
   */
  public constructor() {
    super('none');
  }

  /**
   * Signs a Message using the provided JSON Web Key.
   *
   * @param _message ~Message to be signed.~
   * @param jsonWebKey JSON Web Key used to sign the Message.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the JSON Web Signature Digital Signature Algorithm.
   * @returns Signature of the Message.
   */
  public async sign(_message: Buffer, jsonWebKey: null): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);
    return Buffer.alloc(0);
  }

  /**
   * Checks if the provided Signature and Message match based on the provided JSON Web Key.
   *
   * @param signature Signature to be verified.
   * @param _message ~Message to be matched against the Signature.~
   * @param jsonWebKey JSON Web Key used to verify the Signature.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the JSON Web Signature Digital Signature Algorithm.
   * @throws {InvalidJsonWebSignatureError} Failed to verify the provided JSON Web Signature.
   */
  public async verify(signature: Buffer, _message: Buffer, jsonWebKey: null): Promise<void> {
    this.validateJsonWebKey(jsonWebKey);

    if (signature.byteLength !== 0) {
      throw new InvalidJsonWebSignatureError('The provided JSON Web Signature is invalid.');
    }
  }

  /**
   * Checks if the provided JSON Web Key can be used.
   *
   * @param jsonWebKey JSON Web Key to be checked.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the JSON Web Signature Digital Signature Algorithm.
   */
  private validateJsonWebKey(jsonWebKey: null): void {
    if (jsonWebKey !== null) {
      throw new InvalidJsonWebKeyError('The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.');
    }
  }
}
