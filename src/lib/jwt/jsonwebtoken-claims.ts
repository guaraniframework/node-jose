import { Buffer } from 'buffer';

import { isNonEmptyString, isPlainObject, jsonStringify, removeNullishValues } from '@guarani/primitives';

import { InvalidJsonWebTokenClaimsError } from '../errors/invalid-jsonwebtoken-claims.error';
import { JsonWebTokenClaimsParameters } from './jsonwebtoken-claims.parameters';

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
   * @throws {InvalidJsonWebTokenClaimsError} The provided JSON Web Token Claims Parameters are invalid.
   */
  public constructor(parameters: JsonWebTokenClaimsParameters) {
    (<typeof JsonWebTokenClaims>this.constructor).validateJsonWebTokenClaimsParameters(parameters);
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
      this.validateJsonWebTokenClaimsParameters(parameters as JsonWebTokenClaimsParameters);
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
   * Validates the provided JSON Web Token Claims Parameters.
   *
   * @param claims JSON Web Token Claims Parameters.
   * @throws {InvalidJsonWebTokenClaimsError} The provided JSON Web Token Claims Parameters are invalid.
   */
  protected static validateJsonWebTokenClaimsParameters(claims: JsonWebTokenClaimsParameters): void {
    if (!isPlainObject(claims)) {
      throw new TypeError('The provided JSON Web Token Claims Parameters is invalid.');
    }

    const now = Math.floor(Date.now() / 1000);

    if ('iss' in claims && !isNonEmptyString(claims.iss)) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "iss".');
    }

    if ('sub' in claims && !isNonEmptyString(claims.sub)) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "sub".');
    }

    if ('aud' in claims) {
      if (!isNonEmptyString(claims.aud) && !Array.isArray(claims.aud)) {
        throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "aud".');
      }

      if (
        Array.isArray(claims.aud) &&
        (claims.aud.length === 0 ||
          claims.aud.some((aud) => !isNonEmptyString(aud)) ||
          claims.aud.length !== new Set(claims.aud).size)
      ) {
        throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "aud".');
      }
    }

    if ('exp' in claims && (typeof claims.exp !== 'number' || !Number.isSafeInteger(claims.exp) || claims.exp < now)) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "exp".');
    }

    if ('nbf' in claims && (typeof claims.nbf !== 'number' || !Number.isSafeInteger(claims.nbf) || claims.nbf > now)) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "nbf".');
    }

    if ('iat' in claims && (typeof claims.iat !== 'number' || !Number.isSafeInteger(claims.iat))) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "iat".');
    }

    if ('jti' in claims && !isNonEmptyString(claims.jti)) {
      throw new InvalidJsonWebTokenClaimsError('Invalid JSON Web Token Claim "jti".');
    }
  }
}
