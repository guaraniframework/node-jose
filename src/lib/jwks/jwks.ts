import { removeNullishValues } from '@guarani/primitives';

import { InvalidJwksException } from '../exceptions/invalid-jwks.exception';
import { JwkNotFoundException } from '../exceptions/jwk-not-found.exception';
import { Jwk } from '../jwk/jwk';
import { JwkParams } from '../jwk/jwk.params';
import { JwksParams } from './jwks.params';

/**
 * Implementation of a JWK Set.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-5|RFC 7517 JWK Set}
 */
export class Jwks {
  /**
   * JWK Set Keys Parameter.
   *
   * Array of JWK values.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-5.1|RFC 7517 "keys" parameter}
   */
  public readonly keys!: Jwk[];

  /**
   * Instantiates a new JWK Set.
   *
   * @param keys JWKs to be registered at the JWK Set.
   * @throws {TypeError} The provided Keys argument is invalid.
   * @throws {InvalidJwksException} The provided JWKs are invalid.
   */
  public constructor(keys: Jwk[]) {
    if (!Array.isArray(keys) || keys.length === 0 || keys.some((key) => !(key instanceof Jwk))) {
      throw new TypeError('Invalid parameter "keys".');
    }

    keys.forEach((key) => (key.kid ??= key.getThumbprint().toString('base64url')));

    const identifiers = keys.map((key) => key.kid);

    if (new Set(identifiers).size !== identifiers.length) {
      throw new InvalidJwksException('The use of duplicate key identifiers is forbidden.');
    }

    this.keys = keys;
  }

  /**
   * Finds and returns a JWK that satisfies the provided predicate.
   *
   * @param predicate Predicate used to locate the requested JWK.
   * @returns JWK that satisfies the provided predicate.
   */
  public find<T extends Jwk>(predicate: (key: JwkParams) => boolean): T | null {
    return <T>this.keys.find(predicate) ?? null;
  }

  /**
   * Finds and returns a JWK that satisfies the provided predicate or throws an exception if none is found.
   *
   * @param predicate Predicate used to locate the requested JWK.
   * @throws {JwkNotFoundException} No JWK matches the criteria at the JWK Set.
   * @returns JWK that satisfies the provided predicate.
   */
  public get<T extends Jwk>(predicate: (key: JwkParams) => boolean): T {
    const key = this.find(predicate);

    if (key === null) {
      throw new JwkNotFoundException();
    }

    return key as T;
  }

  /**
   * Returns the JWK Set Parameters.
   */
  public toJSON(): JwksParams {
    return removeNullishValues<JwksParams>({ keys: this.keys.map((key) => key.toJSON()) });
  }
}
