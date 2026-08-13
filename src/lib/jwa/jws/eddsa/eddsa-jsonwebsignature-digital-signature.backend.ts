import { Buffer } from 'buffer';
import { sign, verify } from 'crypto';
import { promisify } from 'util';

import { InvalidJsonWebKeyError } from '../../../errors/invalid-jsonwebkey.error';
import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { EdwardsCurve } from '../../jwk/okp/edwards-curve.type';
import { OctetKeyPairJsonWebKey } from '../../jwk/okp/octet-key-pair.jsonwebkey';
import { JsonWebSignatureDigitalSignatureBackend } from '../jsonwebsignature-digital-signature.backend';

const signAsync = promisify(sign);
const verifyAsync = promisify(verify);

/**
 * Implementation of the EdDSA JSON Web Signature Digital Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1|RFC 8037 Signatures}
 */
export class EdDSAJsonWebSignatureDigitalSignatureBackend extends JsonWebSignatureDigitalSignatureBackend {
  /**
   * Supported Edwards Curves.
   */
  static readonly #curves: EdwardsCurve[] = ['Ed25519', 'Ed448'];

  /**
   * Instantiates a new EdDSA JSON Web Signature Digital Signature Backend.
   */
  public constructor() {
    super('EdDSA');
  }

  /**
   * Signs a Message using the provided JSON Web Key.
   *
   * @param message Message to be signed.
   * @param jsonWebKey JSON Web Key used to sign the Message.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key cannot be used by the JSON Web Signature Digital Signature Algorithm.
   * @returns Signature of the Message.
   */
  public async sign(message: Buffer, jsonWebKey: OctetKeyPairJsonWebKey): Promise<Buffer> {
    this.validateJsonWebKey(jsonWebKey);

    if (jsonWebKey.cryptoKey.type !== 'private') {
      throw new InvalidJsonWebKeyError('The provided JSON Web Key cannot be used to sign a Message.');
    }

    return await signAsync(null, message, jsonWebKey.cryptoKey);
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
  public async verify(signature: Buffer, message: Buffer, jsonWebKey: OctetKeyPairJsonWebKey): Promise<void> {
    this.validateJsonWebKey(jsonWebKey);

    const result = await verifyAsync(null, message, jsonWebKey.cryptoKey, signature);

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
  private validateJsonWebKey(jsonWebKey: OctetKeyPairJsonWebKey): void {
    if (
      !(jsonWebKey instanceof JsonWebKey) ||
      ('alg' in jsonWebKey.parameters && jsonWebKey.parameters.alg !== this.algorithm)
    ) {
      throw new InvalidJsonWebKeyError('The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.');
    }

    if (jsonWebKey.parameters.kty !== 'OKP') {
      throw new InvalidJsonWebKeyError('The JSON Web Signature Algorithm only accepts "OKP" JSON Web Keys.');
    }

    if (!EdDSAJsonWebSignatureDigitalSignatureBackend.#curves.includes(jsonWebKey.parameters.crv as EdwardsCurve)) {
      throw new InvalidJsonWebKeyError('The JSON Web Key Parameter "crv" must be "Ed25519" or "Ed448".');
    }
  }
}
