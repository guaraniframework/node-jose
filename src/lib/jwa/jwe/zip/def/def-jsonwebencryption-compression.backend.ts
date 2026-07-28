import { Buffer } from 'buffer';
import { promisify } from 'util';
import { deflateRaw, inflateRaw } from 'zlib';

import { CompressionAlgorithm } from '../compression-algorithm.type';
import { JsonWebEncryptionCompressionBackend } from '../jsonwebencryption-compression.backend';

const deflateRawAsync = promisify(deflateRaw);
const inflateRawAsync = promisify(inflateRaw);

/**
 * Implementation of the DEF JSON Web Encryption Compression Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3|RFC 7516 "zip" (Compression Algorithm) Header Parameter}
 */
export class DEFJsonWebEncryptionCompressionBackend extends JsonWebEncryptionCompressionBackend {
  /**
   * JSON Web Encryption Compression Algorithm.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3|RFC 7516 "zip" (Compression Algorithm) Header Parameter}
   */
  declare protected readonly algorithm: Extract<CompressionAlgorithm, 'DEF'>;

  /**
   * Instantiates a new DEF JSON Web Encryption Compression Backend.
   */
  public constructor() {
    super('DEF');
  }

  /**
   * Compresses the provided Plaintext.
   *
   * @param plaintext Plaintext to be compressed.
   * @returns Compressed Plaintext.
   */
  public async compress(plaintext: Buffer): Promise<Buffer> {
    return await deflateRawAsync(plaintext);
  }

  /**
   * Decompresses the provided Plaintext.
   *
   * @param plaintext Plaintext to be decompressed.
   * @returns Decompressed Plaintext.
   */
  public async decompress(plaintext: Buffer): Promise<Buffer> {
    return await inflateRawAsync(plaintext);
  }
}
