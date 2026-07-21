/**
 * Cryptographic algorithm family used with the key.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" (Key Type) Parameter}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" (Key Type) Parameter Values}
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2|RFC 8037 Key Type "OKP"}
 */
export type KeyType = 'EC' | 'OKP' | 'RSA' | 'oct';
