import { JoseHeaderParameters } from '../jose/jose-header.parameters';
import { KeyManagementAlgorithm } from '../jwa/jwe/alg/key-management-algorithm.type';
import { ContentEncryptionAlgorithm } from '../jwa/jwe/enc/content-encryption-algorithm.type';
import { CompressionAlgorithm } from '../jwa/jwe/zip/compression-algorithm.type';

/**
 * JSON Web Encryption Header Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1|RFC 7516 Registered Header Parameter Names}
 */
export interface JsonWebEncryptionHeaderParameters extends JoseHeaderParameters {
  /**
   * JSON Web Encryption Algorithm.
   *
   * Cryptographic algorithm used to encrypt or determine the value of the CEK.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1|RFC 7516 "alg" (Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWE}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2|RFC 8037 ECDH-ES}
   */
  readonly alg: KeyManagementAlgorithm;

  /**
   * JSON Web Encryption Encryption Algorithm.
   *
   * Content encryption algorithm used to perform authenticated encryption
   * on the plaintext to produce the ciphertext and the Authentication Tag.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.2|RFC 7516 "enc" (Encryption Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1|RFC 7518 "enc" (Encryption Algorithm) Header Parameter Values for JWE}
   */
  readonly enc: ContentEncryptionAlgorithm;

  /**
   * JSON Web Encryption Encryption Algorithm.
   *
   * Compression algorithm used to perform compression on the plaintext.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3|RFC 7516 "zip" (Compression Algorithm) Header Parameter}
   */
  readonly zip?: CompressionAlgorithm;
}
