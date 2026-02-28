import { createPrivateKey } from 'crypto';

import { removeNullishValues } from '@guarani/primitives';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { EcPrivateJwkParams } from './ec-private-jwk.params';
import { EcPublicJwk } from './ec-public-jwk';

/**
 * Implementation of an EC Private JWK.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.2|RFC 7518 "EC" Private JWK}
 */
export class EcPrivateJwk extends EcPublicJwk implements EcPrivateJwkParams {
  /**
   * JWK ECC Private Key.
   *
   * Contains the Elliptic Curve private key value.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.2.1|RFC 7518 "d" parameter}
   */
  public readonly d!: string;

  /**
   * Instantiates a new EC Private JWK.
   *
   * @param params EC Private JWK Parameters.
   * @throws {TypeError} The provided JWK Parameters argument is invalid.
   * @throws {InvalidJwkException} The provided JWK Parameters are invalid.
   */
  public constructor(params: EcPrivateJwkParams) {
    super(params);
    Object.assign(this, removeNullishValues(params));
    this.cryptoKey = createPrivateKey({ format: 'jwk', key: params });
  }

  /**
   * Validates the provided EC Private JWK Parameters.
   *
   * @param params EC Private JWK Parameters.
   */
  protected override validateJwkParameters(params: EcPrivateJwkParams): void {
    if (typeof params.d !== 'string') {
      throw new InvalidJwkException('Invalid jwk parameter "d".');
    }

    super.validateJwkParameters(params);
  }
}
