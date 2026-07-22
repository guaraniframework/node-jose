import {
  createPrivateKey,
  createPublicKey,
  generateKeyPair,
  JsonWebKeyInput as CryptoJsonWebKeyInput,
  KeyObject,
} from 'crypto';
import { promisify } from 'util';

import { isNonEmptyString, isPlainObject } from '@guarani/primitives';

import { InvalidJsonWebKeyError } from '../../../errors/invalid-jsonwebkey.error';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { EdwardsMontgomeryCurve } from './edwards-montgomery-curve.type';
import { GenerateOctetKeyPairJsonWebKeyOptions } from './generate-octet-key-pair-jsonwebkey.options';
import { OctetKeyPairJsonWebKeyParameters } from './octet-key-pair-jsonwebkey.parameters';

const generateKeyPairAsync = promisify(generateKeyPair);

/**
 * Implementation of the Octet Key Pair JSON Web Key.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2|RFC 8037 Key Type "OKP"}
 */
export class OctetKeyPairJsonWebKey extends JsonWebKey {
  /**
   * Supported JSON Web Key Octet Key Pair Curves.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1|RFC 8037 Signature}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2|RFC 8037 ECDH-ES}
   */
  static readonly #curves: Record<EdwardsMontgomeryCurve, string> = {
    Ed25519: 'ed25519',
    Ed448: 'ed448',
    X25519: 'x25519',
    X448: 'x448',
  };

  /**
   * JSON Web Key Parameters.
   */
  declare public readonly parameters: OctetKeyPairJsonWebKeyParameters;

  /**
   * Returns a JSON Web Key Backend with generated JSON Web Key Parameters.
   *
   * @param options JSON Web Key Parameters Generation Options.
   * @throws {TypeError} The provided options is invalid.
   * @returns JSON Web Key Backend with the Generated JSON Web Key Parameters.
   */
  public static async generate(options: GenerateOctetKeyPairJsonWebKeyOptions): Promise<KeyObject> {
    if (!isPlainObject(options) || !('curve' in options)) {
      throw new TypeError('The provided options is invalid.');
    }

    if (!(options.curve in this.#curves)) {
      throw new TypeError('The provided Curve is invalid.');
    }

    const { privateKey } = await generateKeyPairAsync(this.#curves[options.curve] as any);

    return privateKey;
  }

  /**
   * Validates the provided JSON Web Key Parameters.
   *
   * @param parameters JSON Web Key Parameters.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters are invalid.
   */
  protected static override validateJsonWebKeyParameters(parameters: OctetKeyPairJsonWebKeyParameters): void {
    if (!isNonEmptyString(parameters.crv) || !Reflect.has(OctetKeyPairJsonWebKey.#curves, parameters.crv)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "crv".');
    }

    if (!isNonEmptyString(parameters.x)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "x".');
    }

    if ('d' in parameters && !isNonEmptyString(parameters.d)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "d".');
    }

    super.validateJsonWebKeyParameters(parameters);
  }

  /**
   * Creates a native Crypto Key.
   *
   * @returns Native Crypto Key.
   */
  protected getCryptoKey(): KeyObject {
    const input: CryptoJsonWebKeyInput = { format: 'jwk', key: this.parameters };
    return 'd' in this.parameters ? createPrivateKey(input) : createPublicKey(input);
  }

  /**
   * Returns the Private Parameters of the JSON Web Key.
   *
   * @returns JSON Web Key Private Parameters.
   */
  protected getPrivateParameters(): string[] {
    return ['d'];
  }

  /**
   * Returns the JSON Web Key Thumbprint Parameters in lexicographic order.
   *
   * @returns JSON Web Key Thumbprint Parameters.
   */
  protected getThumbprintParameters(): OctetKeyPairJsonWebKeyParameters {
    return { crv: this.parameters.crv, kty: this.parameters.kty, x: this.parameters.x };
  }
}
