import { create } from './create';
import { generate } from './generate';

interface JsonWebKeyMethods {
  /**
   * Creates a JSON Web Key based on the provided Parameters.
   *
   * @param parameters JSON Web Key Parameters.
   * @throws {TypeError} The provided JSON Web Key Parameters is invalid.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters are invalid.
   * @returns JSON Web Key.
   */
  readonly create: typeof create;

  /**
   * Generates a JSON Web Key based on the provided options.
   *
   * @param keyType JSON Web Key Key Type.
   * @param options JSON Web Key Generation Options.
   * @throws {TypeError} One of the provided arguments is invalid.
   * @returns Generated JSON Web Key.
   */
  readonly generate: typeof generate;
}

export const jwk: JsonWebKeyMethods = {
  create,
  generate,
};
