import { EllipticCurve } from './elliptic-curve.type';

/**
 * Elliptic Curve JSON Web Key generation options.
 */
export interface GenerateEllipticCurveJsonWebKeyOptions {
  /**
   * Name of the Elliptic Curve.
   */
  readonly curve: EllipticCurve;
}
