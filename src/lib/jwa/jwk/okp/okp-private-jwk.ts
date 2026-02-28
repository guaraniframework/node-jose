import { createPrivateKey } from 'crypto';

import { removeNullishValues } from '@guarani/primitives';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { OkpPrivateJwkParams } from './okp-private-jwk.params';
import { OkpPublicJwk } from './okp-public-jwk';

/**
 * Implementation of an OKP Private JWK.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html|RFC 8037 "OKP" Private JWK}
 */
export class OkpPrivateJwk extends OkpPublicJwk implements OkpPrivateJwkParams {
  /**
   * JWK OKP Private Key.
   *
   * Contains the private key encoded using the base64url encoding.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2|RFC 8037 "d" parameter}
   */
  public readonly d!: string;

  /**
   * Instantiates a new OKP Private JWK.
   *
   * @param params OKP Private JWK Parameters.
   * @throws {TypeError} The provided JWK Parameters argument is invalid.
   * @throws {InvalidJwkException} The provided JWK Parameters are invalid.
   */
  public constructor(params: OkpPrivateJwkParams) {
    super(params);
    Object.assign(this, removeNullishValues(params));
    this.cryptoKey = createPrivateKey({ format: 'jwk', key: params });
  }

  /**
   * Validates the provided OKP Private JWK Parameters.
   *
   * @param params OKP Private JWK Parameters.
   */
  protected override validateJwkParameters(params: OkpPrivateJwkParams): void {
    if (typeof params.d !== 'string') {
      throw new InvalidJwkException('Invalid jwk parameter "d".');
    }

    super.validateJwkParameters(params);
  }
}
