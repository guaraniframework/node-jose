/**
 * Identifies the cryptographic curve used with the key.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.1|RFC 7518 "crv" (Curve) Parameter}
 * @see {@link https://www.rfc-editor.org/rfc/rfc8812.html#section-3.1|RFC 8812 JOSE secp256k1 Curve Key Representation}
 */
export type EllipticCurve = 'P-256' | 'P-384' | 'P-521' | 'secp256k1';
