import { createPrivateKey } from 'crypto';

import { removeNullishValues } from '@guarani/primitives';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { RsaPrivateJwkParams } from './rsa-private-jwk.params';
import { RsaPublicJwk } from './rsa-public-jwk';

/**
 * Implementation of an RSA Private JWK.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2|RFC 7518 "RSA" Private JWK}
 */
export class RsaPrivateJwk extends RsaPublicJwk implements RsaPrivateJwkParams {
  /**
   * JWK Private Exponent.
   *
   * Contains the private exponent value for the RSA private key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.1|RFC 7518 "d" parameter}
   */
  public readonly d!: string;

  /**
   * JWK First Prime Factor.
   *
   * Contains the first prime factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.2|RFC 7518 "p" parameter}
   */
  public readonly p!: string;

  /**
   * JWK Second Prime Factor.
   *
   * Contains the second prime factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.3|RFC 7518 "q" parameter}
   */
  public readonly q!: string;

  /**
   * JWK First Factor CRT Exponent.
   *
   * Contains the Chinese Remainder Theorem (CRT) exponent of the first factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.4|RFC 7518 "dp" parameter}
   */
  public readonly dp!: string;

  /**
   * JWK Second Factor CRT Exponent.
   *
   * Contains the Chinese Remainder Theorem (CRT) exponent of the second factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.5|RFC 7518 "dq" parameter}
   */
  public readonly dq!: string;

  /**
   * JWK First CRT Coefficient.
   *
   * Contains contains the Chinese Remainder Theorem (CRT) coefficient of the second factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.6|RFC 7518 "qi" parameter}
   */
  public readonly qi!: string;

  /**
   * Instantiates a new RSA Private JWK.
   *
   * @param params RSA Private JWK Parameters.
   * @throws {TypeError} The provided JWK Parameters argument is invalid.
   * @throws {InvalidJwkException} The provided JWK Parameters are invalid.
   */
  public constructor(params: RsaPrivateJwkParams) {
    super(params);
    Object.assign(this, removeNullishValues(params));
    this.cryptoKey = createPrivateKey({ format: 'jwk', key: params });
  }

  /**
   * Validates the provided RSA Private JWK Parameters.
   *
   * @param params RSA Private JWK Parameters.
   */
  protected override validateJwkParameters(params: RsaPrivateJwkParams): void {
    if (typeof params.d !== 'string') {
      throw new InvalidJwkException('Invalid jwk parameter "d".');
    }

    if (typeof params.p !== 'string') {
      throw new InvalidJwkException('Invalid jwk parameter "p".');
    }

    if (typeof params.q !== 'string') {
      throw new InvalidJwkException('Invalid jwk parameter "q".');
    }

    if (typeof params.dp !== 'string') {
      throw new InvalidJwkException('Invalid jwk parameter "dp".');
    }

    if (typeof params.dq !== 'string') {
      throw new InvalidJwkException('Invalid jwk parameter "dq".');
    }

    if (typeof params.qi !== 'string') {
      throw new InvalidJwkException('Invalid jwk parameter "qi".');
    }

    super.validateJwkParameters(params);
  }
}
