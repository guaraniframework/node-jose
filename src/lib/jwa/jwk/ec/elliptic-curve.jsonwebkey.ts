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
import { EllipticCurve } from './elliptic-curve.type';
import { EllipticCurveJsonWebKeyParameters } from './elliptic-curve-jsonwebkey.parameters';
import { GenerateEllipticCurveJsonWebKeyOptions } from './generate-elliptic-curve-jsonwebkey.options';

const generateKeyPairAsync = promisify(generateKeyPair);

/**
 * Implementation of the Elliptic Curve JSON Web Key.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2|RFC 7518 Parameters for Elliptic Curve Keys}
 */
export class EllipticCurveJsonWebKey extends JsonWebKey {
  /**
   * Supported JSON Web Key Elliptic Curves.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.1|RFC 7518 "crv" (Curve) Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8812.html#section-3.1|RFC 8812 JOSE secp256k1 Curve Key Representation}
   */
  static readonly #curves: Record<EllipticCurve, string> = {
    'P-256': 'prime256v1',
    'P-384': 'secp384r1',
    'P-521': 'secp521r1',
    secp256k1: 'secp256k1',
  };

  /**
   * JSON Web Key Parameters.
   */
  declare public readonly parameters: EllipticCurveJsonWebKeyParameters;

  /**
   * Returns a JSON Web Key Backend with generated JSON Web Key Parameters.
   *
   * @param options JSON Web Key Parameters Generation Options.
   * @throws {TypeError} The provided options is invalid.
   * @returns JSON Web Key Backend with the Generated JSON Web Key Parameters.
   */
  public static async generate(options: GenerateEllipticCurveJsonWebKeyOptions): Promise<KeyObject> {
    if (!isPlainObject(options) || !('curve' in options)) {
      throw new TypeError('The provided options is invalid.');
    }

    if (!(options.curve in this.#curves)) {
      throw new TypeError('The provided Elliptic Curve is invalid.');
    }

    const { privateKey } = await generateKeyPairAsync('ec', { namedCurve: this.#curves[options.curve] });

    return privateKey;
  }

  /**
   * Validates the provided JSON Web Key Parameters.
   *
   * @param parameters JSON Web Key Parameters.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters are invalid.
   */
  protected static override validateJsonWebKeyParameters(parameters: EllipticCurveJsonWebKeyParameters): void {
    if (!isNonEmptyString(parameters.crv) || !Reflect.has(EllipticCurveJsonWebKey.#curves, parameters.crv)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "crv".');
    }

    if (!isNonEmptyString(parameters.x)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "x".');
    }

    if (!isNonEmptyString(parameters.y)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "y".');
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
  protected getThumbprintParameters(): EllipticCurveJsonWebKeyParameters {
    return { crv: this.parameters.crv, kty: this.parameters.kty, x: this.parameters.x, y: this.parameters.y };
  }
}
