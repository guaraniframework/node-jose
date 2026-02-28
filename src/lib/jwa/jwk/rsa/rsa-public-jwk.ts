import { Buffer } from 'buffer';
import { createPublicKey } from 'crypto';

import { removeNullishValues } from '@guarani/primitives';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { Jwk } from '../../../jwk/jwk';
import { RsaPublicJwkParams } from './rsa-public-jwk.params';

/**
 * Implementation of an RSA Public JWK.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1|RFC 7518 "RSA" Public JWK}
 */
export class RsaPublicJwk extends Jwk<RsaPublicJwkParams> implements RsaPublicJwkParams {
  /**
   * JWK Key Type.
   *
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3|RFC 7518 "kty" parameter}
   */
  public readonly kty!: 'RSA';

  /**
   * JWK Modulus.
   *
   * Contains the modulus value for the RSA public key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1.1|RFC 7518 "n" parameter}
   */
  public readonly n!: string;

  /**
   * JWK Exponent.
   *
   * Contains the exponent value for the RSA public key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1.2|RFC 7518 "e" parameter}
   */
  public readonly e!: string;

  /**
   * Instantiates a new RSA Public JWK.
   *
   * @param params RSA Public JWK Parameters.
   * @throws {TypeError} The provided JWK Parameters argument is invalid.
   * @throws {InvalidJwkException} The provided JWK Parameters are invalid.
   */
  public constructor(params: RsaPublicJwkParams) {
    super(params);
    Object.assign(this, removeNullishValues(params));
    this.cryptoKey = createPublicKey({ format: 'jwk', key: params });
  }

  /**
   * Validates the provided RSA Public JWK Parameters.
   *
   * @param params RSA Public JWK Parameters.
   */
  protected override validateJwkParameters(params: RsaPublicJwkParams): void {
    if (params.kty !== 'RSA') {
      throw new InvalidJwkException(`Invalid jwk parameter "kty". Expected "RSA", got "${String(params.kty)}".`);
    }

    if (typeof params.n !== 'string' || Buffer.byteLength(params.n, 'base64url') < 256) {
      throw new InvalidJwkException('Invalid jwk parameter "n".');
    }

    if (typeof params.e !== 'string') {
      throw new InvalidJwkException('Invalid jwk parameter "e".');
    }

    super.validateJwkParameters(params);
  }

  /**
   * Returns the parameters used to calculate the RSA JWK Thumbprint in lexicographic order.
   */
  protected getThumbprintParameters(): RsaPublicJwkParams {
    return { e: this.e, kty: this.kty, n: this.n };
  }
}
