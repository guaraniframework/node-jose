import { createPublicKey } from 'crypto';

import { removeNullishValues } from '@guarani/primitives';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { Jwk } from '../../../jwk/jwk';
import { JwkCrv } from '../jwk-crv.type';
import { OkpPublicJwkParams } from './okp-public-jwk.params';

/**
 * Implementation of an OKP Public JWK.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html|RFC 8037 "OKP" Public JWK}
 */
export class OkpPublicJwk extends Jwk<OkpPublicJwkParams> implements OkpPublicJwkParams {
  /**
   * JWK Key Type.
   *
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2|RFC 8037 "kty" parameter}
   */
  public readonly kty!: 'OKP';

  /**
   * JWK Curve.
   *
   * Identifies the cryptographic curve used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2|RFC 8037 "crv" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1|RFC 8037 EdDSA "crv" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2|RFC 8037 ECDH-ES "crv" parameter}
   */
  public readonly crv!: Extract<JwkCrv, 'Ed25519' | 'Ed448' | 'X25519' | 'X448'>;

  /**
   * JWK OKP Public Key.
   *
   * Contains the public key encoded using the base64url encoding.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2|RFC 8037 "x" parameter}
   */
  public readonly x!: string;

  /**
   * Elliptic Curves supported by the OKP JWK.
   */
  public static get supportedEllipticCurves(): Extract<JwkCrv, 'Ed25519' | 'Ed448' | 'X25519' | 'X448'>[] {
    return ['Ed25519', 'Ed448', 'X25519', 'X448'];
  }

  /**
   * Instantiates a new OKP Public JWK.
   *
   * @param params OKP Public JWK Parameters.
   * @throws {TypeError} The provided JWK Parameters argument is invalid.
   * @throws {InvalidJwkException} The provided JWK Parameters are invalid.
   */
  public constructor(params: OkpPublicJwkParams) {
    super(params);
    Object.assign(this, removeNullishValues(params));
    this.cryptoKey = createPublicKey({ format: 'jwk', key: params });
  }

  /**
   * Validates the provided OKP Public JWK Parameters.
   *
   * @param params OKP Public JWK Parameters.
   */
  protected override validateJwkParameters(params: OkpPublicJwkParams): void {
    if (params.kty !== 'OKP') {
      throw new InvalidJwkException(`Invalid jwk parameter "kty". Expected "OKP", got "${String(params.kty)}".`);
    }

    if (typeof params.crv !== 'string' || !OkpPublicJwk.supportedEllipticCurves.includes(params.crv)) {
      throw new InvalidJwkException('Invalid jwk parameter "crv".');
    }

    if (typeof params.x !== 'string') {
      throw new InvalidJwkException('Invalid jwk parameter "x".');
    }

    super.validateJwkParameters(params);
  }

  /**
   * Returns the parameters used to calculate the OKP JWK Thumbprint in lexicographic order.
   */
  protected getThumbprintParameters(): OkpPublicJwkParams {
    return { crv: this.crv, kty: this.kty, x: this.x };
  }
}
