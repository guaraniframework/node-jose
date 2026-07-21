/**
 * Cryptographic Algorithms for Key Management.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1|RFC 7516 "alg" (Algorithm) Header Parameter}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWE}
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2|RFC 8037 ECDH-ES}
 */
export type KeyManagementAlgorithm =
  | 'A128GCMKW'
  | 'A128KW'
  | 'A192GCMKW'
  | 'A192KW'
  | 'A256GCMKW'
  | 'A256KW'
  | 'ECDH-ES'
  | 'ECDH-ES+A128KW'
  | 'ECDH-ES+A192KW'
  | 'ECDH-ES+A256KW'
  | 'PBES2-HS256+A128KW'
  | 'PBES2-HS384+A192KW'
  | 'PBES2-HS512+A256KW'
  | 'RSA-OAEP'
  | 'RSA-OAEP-256'
  | 'RSA-OAEP-384'
  | 'RSA-OAEP-512'
  | 'RSA1_5'
  | 'dir';
