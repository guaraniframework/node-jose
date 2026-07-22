import { EdwardsMontgomeryCurve } from './edwards-montgomery-curve.type';

/**
 * Octet Key Pair JSON Web Key generation options.
 */
export interface GenerateOctetKeyPairJsonWebKeyOptions {
  /**
   * Name of the Curve.
   */
  readonly curve: EdwardsMontgomeryCurve;
}
