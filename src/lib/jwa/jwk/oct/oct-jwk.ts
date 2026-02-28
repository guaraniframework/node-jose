import { Buffer } from 'buffer';
import { createSecretKey } from 'crypto';

import { removeNullishValues } from '@guarani/primitives';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { Jwk } from '../../../jwk/jwk';
import { OctJwkParams } from './oct-jwk.params';

/**
 * Implementation of an oct JWK.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4|RFC 7518 "oct" JWK}
 */
export class OctJwk extends Jwk<OctJwkParams> implements OctJwk {
  /**
   * JWK Key Type.
   *
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4|RFC 7518 "kty" parameter}
   */
  public readonly kty!: 'oct';

  /**
   * JWK Key Value.
   *
   * Contains the value of the symmetric key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4.1|RFC 7518 "k" parameter}
   */
  public readonly k!: string;

  /**
   * Instantiates a new oct JWK.
   *
   * @param params oct JWK Parameters.
   * @throws {TypeError} The provided JWK Parameters argument is invalid.
   * @throws {InvalidJwkException} The provided JWK Parameters are invalid.
   */
  public constructor(params: OctJwkParams) {
    super(params);
    Object.assign(this, removeNullishValues(params));
    this.cryptoKey = createSecretKey(params.k, 'base64url');
  }

  /**
   * Validates the provided oct JWK Parameters.
   *
   * @param params oct JWK Parameters.
   */
  protected override validateJwkParameters(params: OctJwkParams): void {
    if (params.kty !== 'oct') {
      throw new InvalidJwkException(`Invalid jwk parameter "kty". Expected "oct", got "${String(params.kty)}".`);
    }

    if (typeof params.k !== 'string' || Buffer.byteLength(params.k, 'base64url') === 0) {
      throw new InvalidJwkException('Invalid jwk parameter "k".');
    }

    super.validateJwkParameters(params);
  }

  /**
   * Returns the parameters used to calculate the oct JWK Thumbprint in lexicographic order.
   */
  protected getThumbprintParameters(): OctJwkParams {
    return { k: this.k, kty: this.kty };
  }
}
