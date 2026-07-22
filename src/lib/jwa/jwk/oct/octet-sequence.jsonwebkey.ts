import { Buffer } from 'buffer';
import { createSecretKey, KeyObject, randomBytes } from 'crypto';
import { promisify } from 'util';

import { isNonEmptyString, isPlainObject } from '@guarani/primitives';

import { InvalidJsonWebKeyError } from '../../../errors/invalid-jsonwebkey.error';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { GenerateOctetSequenceJsonWebKeyOptions } from './generate-octet-sequence-jsonwebkey.options';
import { OctetSequenceJsonWebKeyParameters } from './octet-sequence-jsonwebkey.parameters';

const randomBytesAsync = promisify(randomBytes);

/**
 * Implementation of the Octet Sequence JSON Web Key.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4|RFC 7518 Parameters for Symmetric Keys}
 */
export class OctetSequenceJsonWebKey extends JsonWebKey {
  /**
   * JSON Web Key Parameters.
   */
  declare public readonly parameters: OctetSequenceJsonWebKeyParameters;

  /**
   * Returns a JSON Web Key Backend with generated JSON Web Key Parameters.
   *
   * @param options JSON Web Key Parameters Generation Options.
   * @throws {TypeError} The provided options is invalid.
   * @returns JSON Web Key Backend with the Generated JSON Web Key Parameters.
   */
  public static async generate(options: GenerateOctetSequenceJsonWebKeyOptions): Promise<KeyObject> {
    if (!isPlainObject(options) || !('length' in options)) {
      throw new TypeError('The provided options is invalid.');
    }

    if (!Number.isSafeInteger(options.length) || options.length <= 0) {
      throw new TypeError('The provided Length is invalid.');
    }

    return createSecretKey(await randomBytesAsync(options.length));
  }

  /**
   * Validates the provided JSON Web Key Parameters.
   *
   * @param parameters JSON Web Key Parameters.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters are invalid.
   */
  protected static override validateJsonWebKeyParameters(parameters: OctetSequenceJsonWebKeyParameters): void {
    if (!isNonEmptyString(parameters.k) || Buffer.byteLength(parameters.k, 'base64url') === 0) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "k".');
    }

    super.validateJsonWebKeyParameters(parameters);
  }

  /**
   * Creates a native Crypto Key.
   *
   * @returns Native Crypto Key.
   */
  protected getCryptoKey(): KeyObject {
    return createSecretKey(this.parameters.k, 'base64url');
  }

  /**
   * Returns the Private Parameters of the JSON Web Key.
   *
   * @returns JSON Web Key Private Parameters.
   */
  protected getPrivateParameters(): string[] {
    return [];
  }

  /**
   * Returns the JSON Web Key Thumbprint Parameters in lexicographic order.
   *
   * @returns JSON Web Key Thumbprint Parameters.
   */
  protected getThumbprintParameters(): OctetSequenceJsonWebKeyParameters {
    return { k: this.parameters.k, kty: this.parameters.kty };
  }
}
