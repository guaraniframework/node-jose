import { Buffer } from 'buffer';

import { CompressionAlgorithm } from './compression-algorithm.type';

/**
 * Implementation of the JSON Web Encryption Compression Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3|RFC 7516 "zip" (Compression Algorithm) Header Parameter}
 */
export abstract class JsonWebEncryptionCompressionBackend {
  /**
   * JSON Web Encryption Compression Algorithm.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3|RFC 7516 "zip" (Compression Algorithm) Header Parameter}
   */
  protected readonly algorithm: CompressionAlgorithm;

  /**
   * Instantiates a new JSON Web Encryption Compression Backend.
   *
   * @param algorithm JSON Web Encryption Compression Algorithm.
   */
  public constructor(algorithm: CompressionAlgorithm) {
    this.algorithm = algorithm;
  }

  /**
   * Compresses the provided Plaintext.
   *
   * @param plaintext Plaintext to be compressed.
   * @returns Compressed Plaintext.
   */
  public abstract compress(plaintext: Buffer): Promise<Buffer>;

  /**
   * Decompresses the provided Plaintext.
   *
   * @param plaintext Plaintext to be decompressed.
   * @returns Decompressed Plaintext.
   */
  public abstract decompress(plaintext: Buffer): Promise<Buffer>;
}
