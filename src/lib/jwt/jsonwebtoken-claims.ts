import { Buffer } from 'buffer';
import { isDeepStrictEqual } from 'util';

import { isNonEmptyString, isPlainObject, jsonStringify, removeNullishValues } from '@guarani/primitives';

import { InvalidJsonWebTokenClaimsError } from '../errors/invalid-jsonwebtoken-claims.error';
import { JsonWebTokenClaimsOptions } from './jsonwebtoken-claims.options';
import { JsonWebTokenClaimsParameters } from './jsonwebtoken-claims.parameters';
import { JsonWebTokenClaimValidationOptions } from './jsonwebtoken-claims-validation.options';

/**
 * Implementation of the JSON Web Token Claims.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7519.html#section-4|RFC 7519 JWT Claims}
 */
export class JsonWebTokenClaims {
  /**
   * JSON Web Token Claims.
   */
  public readonly parameters: JsonWebTokenClaimsParameters;

  /**
   * Instantiates a new JSON Web Token Claims.
   *
   * @param parameters JSON Web Token Claims Parameters.
   * @param options JSON Web Token Claims Options.
   * @throws {TypeError} The provided JSON Web Token Claims Parameters is invalid.
   * @throws {InvalidJsonWebTokenClaimsError} The provided JSON Web Token Claims Parameters are invalid.
   */
  public constructor(parameters: JsonWebTokenClaimsParameters, options: JsonWebTokenClaimsOptions = {}) {
    this.validateOptions(options);

    JsonWebTokenClaims.validateDefaultClaims(parameters, options.ignoreExpired);

    (<typeof JsonWebTokenClaims>this.constructor).validateCustomClaims?.(parameters);

    if ('validationOptions' in options) {
      (<typeof JsonWebTokenClaims>this.constructor).validateClaimsOptions(parameters, options.validationOptions);
    }

    this.parameters = removeNullishValues(parameters);
  }

  /**
   * Checks if the provided data is a valid JSON Web Token Claims Parameters object.
   *
   * @param parameters JSON Web Token Claims Parameters.
   * @returns Whether or not the provided data is a valid JSON Web Token Claims Parameters object.
   */
  public static isJsonWebTokenClaimsParameters(parameters: unknown): parameters is JsonWebTokenClaimsParameters {
    try {
      this.validateDefaultClaims(parameters as JsonWebTokenClaimsParameters);
      this.validateCustomClaims?.(parameters as JsonWebTokenClaimsParameters);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Returns the string representation of the JSON Web Token Claims.
   *
   * @returns String representation of the JSON Web Token Claims.
   */
  public toString(): string {
    return jsonStringify(this.parameters);
  }

  /**
   * Returns the buffer representation of the JSON Web Token Claims.
   *
   * @returns Buffer representation of the JSON Web Token Claims.
   */
  public toBuffer(): Buffer {
    return Buffer.from(this.toString(), 'utf8');
  }

  /**
   * Method used when extending JsonWebTokenClaims via inheritance.
   *
   * This method should be implemented by the child class in order to provide validation
   * for custom JSON Web Token Claims supported by it.
   *
   * *Implementation of this method is optional.*
   *
   * @param parameters JSON Web Token Claims.
   * @throws {InvalidJsonWebTokenClaimsError} The provided JSON Web Token Claims Parameters are invalid.
   */
  protected static validateCustomClaims?(parameters: JsonWebTokenClaimsParameters): void;

  /**
   * Validates the provided JSON Web Token Claims Parameters.
   *
   * @param parameters JSON Web Token Claims Parameters.
   * @param ignoreExpired Indicates if the value of the JSON Web Token Claim "exp" should be ignored.
   * @throws {TypeError} The provided JSON Web Token Claims Parameters is invalid.
   * @throws {InvalidJsonWebTokenClaimsError} The provided JSON Web Token Claims Parameters are invalid.
   */
  private static validateDefaultClaims(parameters: JsonWebTokenClaimsParameters, ignoreExpired = false): void {
    if (!isPlainObject(parameters)) {
      throw new TypeError('The provided JSON Web Token Claims Parameters is invalid.');
    }

    const now = Math.floor(Date.now() / 1000);

    if ('iss' in parameters && !isNonEmptyString(parameters.iss)) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "iss".');
    }

    if ('sub' in parameters && !isNonEmptyString(parameters.sub)) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "sub".');
    }

    if ('aud' in parameters) {
      if (!isNonEmptyString(parameters.aud) && !Array.isArray(parameters.aud)) {
        throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "aud".');
      }

      if (
        Array.isArray(parameters.aud) &&
        (parameters.aud.length === 0 ||
          parameters.aud.some((aud) => !isNonEmptyString(aud)) ||
          parameters.aud.length !== new Set(parameters.aud).size)
      ) {
        throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "aud".');
      }
    }

    if (
      'exp' in parameters &&
      (typeof parameters.exp !== 'number' ||
        !Number.isSafeInteger(parameters.exp) ||
        (!ignoreExpired && parameters.exp < now))
    ) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "exp".');
    }

    if (
      'nbf' in parameters &&
      (typeof parameters.nbf !== 'number' || !Number.isSafeInteger(parameters.nbf) || parameters.nbf > now)
    ) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "nbf".');
    }

    if ('iat' in parameters && (typeof parameters.iat !== 'number' || !Number.isSafeInteger(parameters.iat))) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "iat".');
    }

    if ('jti' in parameters && !isNonEmptyString(parameters.jti)) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "jti".');
    }
  }

  /**
   * Validates the provided JSON Web Token Claims based on the provided Options.
   *
   * @param claims JSON Web Token Claims.
   * @param options Dictionary used to validate the provided JSON Web Token Claims.
   * @throws {InvalidJsonWebTokenClaimsError} A JSON Web Token Claim failed the required validation.
   */
  private static validateClaimsOptions(
    claims: JsonWebTokenClaimsParameters,
    options: Record<string, JsonWebTokenClaimValidationOptions | null>,
  ): void {
    Object.entries(options).forEach(([claim, option]) => {
      if (option === null) {
        return;
      }

      if (option.essential === true && !(claim in claims)) {
        throw new InvalidJsonWebTokenClaimsError(`Missing required JSON Web Token Claim "${claim}".`);
      }

      if ('value' in option) {
        if (option.essential === false && !(claim in claims)) {
          return;
        }

        if (!isDeepStrictEqual(claims[claim], option.value, { skipPrototype: true })) {
          throw new InvalidJsonWebTokenClaimsError(`Unexpected value for JSON Web Token Claim "${claim}".`);
        }
      }

      if ('values' in option) {
        if (option.essential === false && !(claim in claims)) {
          return;
        }

        if (!option.values.some((value) => isDeepStrictEqual(value, claims[claim], { skipPrototype: true }))) {
          throw new InvalidJsonWebTokenClaimsError(`Unexpected value for JSON Web Token Claim "${claim}".`);
        }
      }
    });
  }

  /**
   * Validates the provided JSON Web Token Claims Options.
   *
   * @param options JSON Web Token Claims Options to be validated.
   * @throws {TypeError} The provided JSON Web Token Claims Options is invalid.
   */
  private validateOptions(options: JsonWebTokenClaimsOptions): void {
    if (!isPlainObject(options)) {
      throw new TypeError('The provided JSON Web Token Claims Options is invalid.');
    }

    if ('ignoreExpired' in options && typeof options.ignoreExpired !== 'boolean') {
      throw new TypeError('The provided JSON Web Token Claims Option "ignoreExpired" is invalid.');
    }

    if ('validationOptions' in options) {
      if (!isPlainObject(options.validationOptions)) {
        throw new TypeError('The provided JSON Web Token Claims Option "validationOptions" is invalid.');
      }

      Object.values(options.validationOptions).forEach((option) => {
        if (option === null) {
          return;
        }

        if ('essential' in option && typeof option.essential !== 'boolean') {
          throw new TypeError('The provided JSON Web Token Claim Validation Option "essential" is invalid.');
        }

        if ('value' in option && 'values' in option) {
          throw new TypeError('Cannot have both "value" and "values" JSON Web Token Claim Validation Options.');
        }

        if ('values' in option && (!Array.isArray(option.values) || option.values.length === 0)) {
          throw new TypeError('The provided JSON Web Token Claim Validation Option "values" is invalid.');
        }
      });
    }
  }
}
