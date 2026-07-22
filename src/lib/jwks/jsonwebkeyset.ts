import { removeNullishValues } from '@guarani/primitives';

import { InvalidJsonWebKeyError } from '../errors/invalid-jsonwebkey.error';
import { JsonWebKey } from '../jwk/jsonwebkey';
import { JsonWebKeyParameters } from '../jwk/jsonwebkey.parameters';
import { JsonWebKeySetParameters } from './jsonwebkeyset.parameters';

/**
 * Implementation of the JSON Web Key Set.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html|RFC 7517 JSON Web Key (JWK)}
 */
export class JsonWebKeySet {
  /**
   * Array of JWK values.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-5.1|RFC 7517 "keys" Parameter}
   */
  public readonly keys: JsonWebKey[];

  /**
   * Instantiates a new JSON Web Key Set.
   *
   * @param keys JSON Web Keys.
   */
  public constructor(keys: JsonWebKey[]) {
    this.keys = keys;
  }

  /**
   * Finds and returns a JSON Web Key that satisfies the provided predicate.
   *
   * @param predicate Predicate used to locate the requested JSON Web Key.
   * @returns JSON Web Key that satisfies the provided predicate.
   */
  public find(predicate: (key: JsonWebKeyParameters) => boolean): JsonWebKey | null {
    return this.keys.find((key) => predicate(key.parameters)) ?? null;
  }

  /**
   * Finds and returns a JSON Web Key that satisfies the provided predicate or throws an exception if none is found.
   *
   * @param predicate Predicate used to locate the requested JSON Web Key.
   * @throws {InvalidJsonWebKeyError} No JSON Web Key matches the criteria in the JSON Web Key Set.
   * @returns JSON Web Key that satisfies the provided predicate.
   */
  public get(predicate: (key: JsonWebKeyParameters) => boolean): JsonWebKey {
    const key = this.find(predicate);

    if (key === null) {
      throw new InvalidJsonWebKeyError('No JSON Web Key matches the criteria in the JSON Web Key Set.');
    }

    return key;
  }

  /**
   * Returns the JSON Web Key Set Parameters.
   *
   * @param exportPrivate Exports the private parameters of the JSON Web keys.
   * @default exportPrivate false
   * @returns JSON Web Key Set Parameters.
   */
  public toJSON(exportPrivate = false): JsonWebKeySetParameters {
    return removeNullishValues<JsonWebKeySetParameters>({ keys: this.keys.map((key) => key.toJSON(exportPrivate)) });
  }
}
