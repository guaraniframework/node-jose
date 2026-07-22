import { Buffer } from 'buffer';
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
import { GenerateRsaJsonWebKeyOptions } from './generate-rsa-jsonwebkey.options';
import { RsaJsonWebKeyParameters } from './rsa-jsonwebkey.parameters';

const generateKeyPairAsync = promisify(generateKeyPair);

/**
 * Implementation of the RSA JSON Web Key.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3|RFC 7518 Parameters for RSA Keys}
 */
export class RsaJsonWebKey extends JsonWebKey {
  /**
   * JSON Web Key Private Parameters.
   */
  static readonly #privateParameters: string[] = ['d', 'p', 'q', 'dp', 'dq', 'qi'];

  /**
   * JSON Web Key Parameters.
   */
  declare public readonly parameters: RsaJsonWebKeyParameters;

  /**
   * Returns a JSON Web Key Backend with generated JSON Web Key Parameters.
   *
   * @param options JSON Web Key Parameters Generation Options.
   * @throws {TypeError} The provided options is invalid.
   * @returns JSON Web Key Backend with the Generated JSON Web Key Parameters.
   */
  public static async generate(options: GenerateRsaJsonWebKeyOptions): Promise<KeyObject> {
    if (!isPlainObject(options) || !('modulus' in options)) {
      throw new TypeError('The provided options is invalid.');
    }

    if (!Number.isSafeInteger(options.modulus) || options.modulus < 2048) {
      throw new TypeError('The provided Modulus is invalid.');
    }

    if ('publicExponent' in options && (!Number.isSafeInteger(options.publicExponent) || options.publicExponent < 1)) {
      throw new TypeError('The provided Public Exponent is invalid.');
    }

    const { privateKey } = await generateKeyPairAsync('rsa', {
      modulusLength: options.modulus,
      publicExponent: options.publicExponent,
    });

    return privateKey;
  }

  /**
   * Validates the provided JSON Web Key Parameters.
   *
   * @param parameters JSON Web Key Parameters.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters are invalid.
   */
  protected static override validateJsonWebKeyParameters(parameters: RsaJsonWebKeyParameters): void {
    if (!isNonEmptyString(parameters.n) || Buffer.byteLength(parameters.n, 'base64url') < 256) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "n".');
    }

    if (!isNonEmptyString(parameters.e)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "e".');
    }

    if (this.#privateParameters.some((parameter) => parameter in parameters)) {
      if (!isNonEmptyString(parameters.d)) {
        throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "d".');
      }

      if (!isNonEmptyString(parameters.p)) {
        throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "p".');
      }

      if (!isNonEmptyString(parameters.q)) {
        throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "q".');
      }

      if (!isNonEmptyString(parameters.dp)) {
        throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "dp".');
      }

      if (!isNonEmptyString(parameters.dq)) {
        throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "dq".');
      }

      if (!isNonEmptyString(parameters.qi)) {
        throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "qi".');
      }
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
    return RsaJsonWebKey.#privateParameters;
  }

  /**
   * Returns the JSON Web Key Thumbprint Parameters in lexicographic order.
   *
   * @returns JSON Web Key Thumbprint Parameters.
   */
  protected getThumbprintParameters(): RsaJsonWebKeyParameters {
    return { e: this.parameters.e, kty: this.parameters.kty, n: this.parameters.n };
  }
}
