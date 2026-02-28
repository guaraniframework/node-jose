import { createPublicKey } from 'crypto';

import { removeNullishValues } from '@guarani/primitives';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { Jwk } from '../../../jwk/jwk';
import { JwkCrv } from '../jwk-crv.type';
import { EcPublicJwkParams } from './ec-public-jwk.params';

/**
 * Implementation of an EC Public JWK.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1|RFC 7518 "EC" Public JWK}
 */
export class EcPublicJwk extends Jwk<EcPublicJwkParams> implements EcPublicJwkParams {
  /**
   * JWK Key Type.
   *
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2|RFC 7518 "kty" parameter}
   */
  public readonly kty!: 'EC';

  /**
   * JWK Curve.
   *
   * Identifies the cryptographic curve used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.1|RFC 7518 "crv" parameter}
   */
  public readonly crv!: Extract<JwkCrv, 'P-256' | 'P-384' | 'P-521'>;

  /**
   * JWK X Coordinate.
   *
   * Contains the x coordinate for the Elliptic Curve point.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.2|RFC 7518 "x" parameter}
   */
  public readonly x!: string;

  /**
   * JWK Y Coordinate.
   *
   * Contains the y coordinate for the Elliptic Curve point.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.3|RFC 7518 "y" parameter}
   */
  public readonly y!: string;

  /**
   * Elliptic Curves supported by the EC JWK.
   */
  public static get supportedEllipticCurves(): Extract<JwkCrv, 'P-256' | 'P-384' | 'P-521'>[] {
    return ['P-256', 'P-384', 'P-521'];
  }

  /**
   * Instantiates a new EC Public JWK.
   *
   * @param params EC Public JWK Parameters.
   * @throws {TypeError} The provided JWK Parameters argument is invalid.
   * @throws {InvalidJwkException} The provided JWK Parameters are invalid.
   */
  public constructor(params: EcPublicJwkParams) {
    super(params);
    Object.assign(this, removeNullishValues(params));
    this.cryptoKey = createPublicKey({ format: 'jwk', key: params });
  }

  /**
   * Validates the provided EC Public JWK Parameters.
   *
   * @param params EC Public JWK Parameters.
   */
  protected override validateJwkParameters(params: EcPublicJwkParams): void {
    if (params.kty !== 'EC') {
      throw new InvalidJwkException(`Invalid jwk parameter "kty". Expected "EC", got "${String(params.kty)}".`);
    }

    if (typeof params.crv !== 'string' || !EcPublicJwk.supportedEllipticCurves.includes(params.crv)) {
      throw new InvalidJwkException('Invalid jwk parameter "crv".');
    }

    if (typeof params.x !== 'string') {
      throw new InvalidJwkException('Invalid jwk parameter "x".');
    }

    if (typeof params.y !== 'string') {
      throw new InvalidJwkException('Invalid jwk parameter "y".');
    }

    super.validateJwkParameters(params);
  }

  /**
   * Returns the parameters used to calculate the EC JWK Thumbprint in lexicographic order.
   */
  protected getThumbprintParameters(): EcPublicJwkParams {
    return { crv: this.crv, kty: this.kty, x: this.x, y: this.y };
  }
}
