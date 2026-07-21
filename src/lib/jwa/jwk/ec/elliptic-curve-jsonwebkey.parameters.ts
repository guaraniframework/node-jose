import { JsonWebKeyParameters } from '../../../jwk/jsonwebkey.parameters';
import { EllipticCurve } from './elliptic-curve.type';

/**
 * Elliptic Curve JSON Web Key Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2|RFC 7518 Parameters for Elliptic Curve Keys}
 */
export interface EllipticCurveJsonWebKeyParameters extends JsonWebKeyParameters {
  /**
   * Key Type.
   *
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" (Key Type) Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" (Key Type) Parameter Values}
   */
  readonly kty: 'EC';

  /**
   * Curve.
   *
   * Identifies the cryptographic curve used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.1|RFC 7518 "crv" (Curve) Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8812.html#section-3.1|RFC 8812 JOSE secp256k1 Curve Key Representation}
   */
  readonly crv: EllipticCurve;

  /**
   * X Coordinate.
   *
   * Contains the x coordinate for the Elliptic Curve point.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.2|RFC 7518 "x" (X Coordinate) Parameter}
   */
  readonly x: string;

  /**
   * Y Coordinate.
   *
   * Contains the y coordinate for the Elliptic Curve point.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.3|RFC 7518 "y" (Y Coordinate) Parameter}
   */
  readonly y: string;

  /**
   * ECC Private Key.
   *
   * Contains the Elliptic Curve private key value.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.2.1|RFC 7518 "d" (ECC Private Key) Parameter}
   */
  readonly d?: string;
}
