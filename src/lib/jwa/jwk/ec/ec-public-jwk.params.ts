import { JwkParams } from '../../../jwk/jwk.params';
import { JwkCrv } from '../jwk-crv.type';

/**
 * EC Public JWK Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1|RFC 7518 Parameters for Elliptic Curve Public Keys}
 */
export interface EcPublicJwkParams extends JwkParams {
  /**
   * JWK Key Type.
   *
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2|RFC 7518 "kty" parameter}
   */
  readonly kty: 'EC';

  /**
   * JWK Curve.
   *
   * Identifies the cryptographic curve used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.1|RFC 7518 "crv" parameter}
   */
  readonly crv: Extract<JwkCrv, 'P-256' | 'P-384' | 'P-521'>;

  /**
   * JWK X Coordinate.
   *
   * Contains the x coordinate for the Elliptic Curve point.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.2|RFC 7518 "x" parameter}
   */
  readonly x: string;

  /**
   * JWK Y Coordinate.
   *
   * Contains the y coordinate for the Elliptic Curve point.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.3|RFC 7518 "y" parameter}
   */
  readonly y: string;
}
