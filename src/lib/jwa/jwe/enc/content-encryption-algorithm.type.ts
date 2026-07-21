/**
 * Cryptographic Algorithms for Content Encryption.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.2|RFC 7516 "enc" (Encryption Algorithm) Header Parameter}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1|RFC 7518 "enc" (Encryption Algorithm) Header Parameter Values for JWE}
 */
export type ContentEncryptionAlgorithm =
  | 'A128CBC-HS256'
  | 'A128GCM'
  | 'A192CBC-HS384'
  | 'A192GCM'
  | 'A256CBC-HS512'
  | 'A256GCM';
