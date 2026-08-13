import { isPlainObject } from '@guarani/primitives';

import { InvalidJsonWebKeySetError } from '../errors/invalid-jsonwebkeyset.error';
import { jwk } from '../jwk';
import { JsonWebKey } from '../jwk/jsonwebkey';
import { JsonWebKeySet } from './jsonwebkeyset';
import { JsonWebKeySetParameters } from './jsonwebkeyset.parameters';

/**
 * Creates a JSON Web Key Set based on the provided JSON Web Key Set Parameters.
 *
 * @param parameters JSON Web Key Set Parameters.
 * @throws {TypeError} The provided JSON Web Key Set Parameters is invalid.
 * @throws {InvalidJsonWebKeySetError} The provided JSON Web Key Set Parameters are invalid.
 * @returns JSON Web Key Set.
 */
export async function create(parameters: JsonWebKeySetParameters): Promise<JsonWebKeySet>;

/**
 * Creates a JSON Web Key Set based on the provided JSON Web Keys.
 *
 * @param keys JSON Web Keys.
 * @throws {TypeError} The provided JSON Web Keys is invalid.
 * @throws {InvalidJsonWebKeySetError} The provided JSON Web Keys contain duplicate entries.
 * @returns JSON Web Key Set.
 */
export async function create(keys: JsonWebKey[]): Promise<JsonWebKeySet>;

/**
 * Creates a JSON Web Key Set based on the provided JSON Web Key Set Parameters or JSON Web Keys.
 *
 * @param parametersOrKeys JSON Web Key Set Parameters or JSON Web Keys.
 * @throws {TypeError} The provided JSON Web Key Set Parameters or JSON Web Keys is invalid.
 * @throws {InvalidJsonWebKeySetError} The provided JSON Web Key Set Parameters are invalid or
 * the provided JSON Web Keys contain duplicate entries.
 * @returns JSON Web Key Set.
 */
export async function create(parametersOrKeys: JsonWebKeySetParameters | JsonWebKey[]): Promise<JsonWebKeySet> {
  const keys = Array.isArray(parametersOrKeys)
    ? validateJsonWebKeys(parametersOrKeys)
    : await validateJsonWebKeySetParameters(parametersOrKeys);

  return new JsonWebKeySet(keys);
}

/**
 * Validates the provided JSON Web Key Set Parameters.
 *
 * @param parameters JSON Web Key Set Parameters.
 * @throws {TypeError} The provided JSON Web Key Set Parameters is invalid.
 * @throws {InvalidJsonWebKeySetError} The provided JSON Web Key Set Parameters are invalid.
 * @returns JSON Web Keys from the provided JSON Web Key Set Parameters.
 */
async function validateJsonWebKeySetParameters(parameters: JsonWebKeySetParameters): Promise<JsonWebKey[]> {
  if (!isPlainObject(parameters)) {
    throw new TypeError('The provided JSON Web Key Set Parameters is invalid.');
  }

  if (!Array.isArray(parameters.keys) || parameters.keys.length === 0) {
    throw new InvalidJsonWebKeySetError('Invalid JSON Web Key Set Parameter "keys".');
  }

  try {
    const keys = await Promise.all(parameters.keys.map(jwk.create));
    return validateJsonWebKeys(keys);
  } catch (error: unknown) {
    throw new InvalidJsonWebKeySetError('Invalid JSON Web Key Set Parameter "keys".', { cause: error });
  }
}

/**
 * Validates the provided JSON Web Keys.
 *
 * @param keys JSON Web Keys.
 * @throws {TypeError} The provided JSON Web Keys is invalid.
 * @throws {InvalidJsonWebKeySetError} The provided JSON Web Keys contain duplicate entries.
 * @returns Provided JSON Web Keys after validation.
 */
function validateJsonWebKeys(keys: JsonWebKey[]): JsonWebKey[] {
  if (keys.length === 0 || keys.some((key) => !(key instanceof JsonWebKey))) {
    throw new TypeError('The provided JSON Web Keys is invalid.');
  }

  const identifiers = keys.map((key) => key.parameters.kid ?? key.getThumbprint().toString('base64url'));

  if (new Set(identifiers).size !== identifiers.length) {
    throw new InvalidJsonWebKeySetError('The use of duplicate JSON Web Keys is forbidden.');
  }

  return keys;
}
