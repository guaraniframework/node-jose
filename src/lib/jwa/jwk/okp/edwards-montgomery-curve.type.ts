import { EdwardsCurve } from './edwards-curve.type';
import { MontgomeryCurve } from './montgomery-curve.type';

/**
 * Identifies the cryptographic curve used with the key.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1|RFC 8037 Signatures}
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2|RFC 8037 ECDH-ES}
 */
export type EdwardsMontgomeryCurve = EdwardsCurve | MontgomeryCurve;
