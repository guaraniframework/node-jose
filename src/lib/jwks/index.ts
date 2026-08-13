import { create } from './create';

interface JsonWebKeySetMethods {
  /**
   * Creates a JSON Web Key Set based on the provided JSON Web Key Set Parameters or JSON Web Keys.
   *
   * @param parametersOrKeys JSON Web Key Set Parameters or JSON Web Keys.
   * @throws {TypeError} The provided JSON Web Key Set Parameters or JSON Web Keys is invalid.
   * @throws {InvalidJsonWebKeySetError} The provided JSON Web Key Set Parameters are invalid or
   * the provided JSON Web Keys contain duplicate entries.
   * @returns JSON Web Key Set.
   */
  readonly create: typeof create;
}

export const jwks: JsonWebKeySetMethods = {
  create,
};
