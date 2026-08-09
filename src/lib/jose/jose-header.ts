import { X509Certificate } from 'crypto';
import { URL } from 'url';

import { isNonEmptyString, isPlainObject, removeNullishValues } from '@guarani/primitives';

import { InvalidJoseHeaderError } from '../errors/invalid-jose-header.error';
import { JsonWebKey } from '../jwk/jsonwebkey';
import { JoseHeaderParameters } from './jose-header.parameters';

/**
 * Implementation of the JOSE Header.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4|RFC 7515 JOSE Header}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4|RFC 7516 JOSE Header}
 */
export abstract class JoseHeader {
  /**
   * JSON Web Key used by the JOSE Header.
   */
  #jsonWebKey!: JsonWebKey | null;

  /**
   * JSON Web Key X.509 Certificate Chain.
   */
  #certificateChain!: X509Certificate[] | null;

  /**
   * JOSE Header Parameters.
   */
  public readonly parameters: JoseHeaderParameters;

  /**
   * NodeJS Crypto Key.
   */
  public get jsonWebKey(): JsonWebKey | null {
    if (typeof this.#jsonWebKey === 'undefined') {
      this.#jsonWebKey = null;
    }

    return this.#jsonWebKey;
  }

  /**
   * NodeJS Crypto Key.
   */
  public set jsonWebKey(jsonWebKey: JsonWebKey | null) {
    this.#jsonWebKey = jsonWebKey;
  }

  /**
   * JSON Web Key X.509 Certificate Chain.
   */
  public get certificateChain(): X509Certificate[] | null {
    if (typeof this.#certificateChain === 'undefined') {
      this.#certificateChain = null;
    }

    return this.#certificateChain;
  }

  /**
   * JSON Web Key X.509 Certificate Chain.
   */
  public set certificateChain(certificateChain: X509Certificate[] | null) {
    this.#certificateChain = certificateChain;
  }

  /**
   * Instantiates a new JOSE Header.
   *
   * @param parameters JOSE Header Parameters.
   * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters are invalid.
   */
  public constructor(parameters: JoseHeaderParameters) {
    (<typeof JoseHeader>this.constructor).validateJoseHeaderParameters(parameters);
    this.parameters = removeNullishValues(parameters);
  }

  /**
   * Checks if the provided data is a valid JOSE Header Parameters object.
   *
   * @param parameters JOSE Header Parameters.
   * @returns Whether or not the provided data is a valid JOSE Header Parameters object.
   */
  public static isJoseHeaderParameters(parameters: unknown): parameters is JoseHeaderParameters {
    if (!isPlainObject(parameters)) {
      return false;
    }

    try {
      this.validateJoseHeaderParameters(parameters as JoseHeaderParameters);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Validates the provided JOSE Header Parameters.
   *
   * @param parameters JOSE Header Parameters.
   * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters are invalid.
   */
  protected static validateJoseHeaderParameters(parameters: JoseHeaderParameters): void {
    if ('jku' in parameters && (!isNonEmptyString(parameters.jku) || !URL.canParse(parameters.jku))) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "jku".');
    }

    if ('jwk' in parameters && !JsonWebKey.isJsonWebKeyParameters(parameters.jwk)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "jwk".');
    }

    if ('jku' in parameters && 'jwk' in parameters) {
      throw new InvalidJoseHeaderError('Cannot have both "jku" and "jwk" JOSE Header Parameters.');
    }

    if ('kid' in parameters && !isNonEmptyString(parameters.kid)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "kid".');
    }

    if ('x5u' in parameters && (!isNonEmptyString(parameters.x5u) || !URL.canParse(parameters.x5u))) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "x5u".');
    }

    if ('x5c' in parameters && !this.checkIfX5CIsANonEmptyArrayOfStrings(parameters.x5c)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "x5c".');
    }

    if ('x5t' in parameters && !isNonEmptyString(parameters.x5t)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "x5t".');
    }

    if ('x5t#S256' in parameters && !isNonEmptyString(parameters['x5t#S256'])) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "x5t#S256".');
    }

    if ('x5u' in parameters && 'x5c' in parameters) {
      throw new InvalidJoseHeaderError('Cannot have both "x5u" and "x5c" JOSE Header Parameters.');
    }

    if (('x5t' in parameters || 'x5t#S256' in parameters) && !('x5u' in parameters) && !('x5c' in parameters)) {
      throw new InvalidJoseHeaderError(
        'Cannot have an X.509 Certificate Thumbprint without an X.509 Certificate Chain.',
      );
    }

    if ('typ' in parameters && !isNonEmptyString(parameters.typ)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "typ".');
    }

    if ('cty' in parameters && !isNonEmptyString(parameters.cty)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "cty".');
    }

    if ('crit' in parameters) {
      if (!this.checkIfCritIsANonEmptyArrayOfStrings(parameters.crit)) {
        throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "crit".');
      }

      parameters.crit.forEach((parameter) => {
        if (!(parameter in parameters)) {
          throw new InvalidJoseHeaderError(`Missing required JOSE Header Parameter "${parameter}".`);
        }
      });
    }
  }

  // #region Helper Methods
  private static checkIfX5CIsANonEmptyArrayOfStrings(x5c: unknown): x5c is string[] {
    return Array.isArray(x5c) && x5c.length !== 0 && x5c.every((certificate) => isNonEmptyString(certificate));
  }

  private static checkIfCritIsANonEmptyArrayOfStrings(crit: unknown): crit is string[] {
    return Array.isArray(crit) && crit.length !== 0 && crit.every((parameter) => isNonEmptyString(parameter));
  }
  // #endregion
}
