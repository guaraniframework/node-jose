import { Buffer } from 'buffer';

import { KeyManagementAlgorithm } from '../../../jwa/jwe/alg/key-management-algorithm.type';
import { ContentEncryptionAlgorithm } from '../../../jwa/jwe/enc/content-encryption-algorithm.type';
import { CompressionAlgorithm } from '../../../jwa/jwe/zip/compression-algorithm.type';
import { JsonWebKey } from '../../../jwk/jsonwebkey';

/**
 * Compact JSON Web Encryption deserialization options.
 */
export interface CompactJsonWebEncryptionDeserializationOptions {
  /**
   * JSON Web Key.
   */
  readonly jsonWebKey?: JsonWebKey;

  /**
   * Expected JSON Web Encryption Key Management Algorithms.
   */
  readonly expectedKeyManagementAlgorithms?: KeyManagementAlgorithm[];

  /**
   * Expected JSON Web Encryption Content Encryption Algorithms.
   */
  readonly expectedContentEncryptionAlgorithms?: ContentEncryptionAlgorithm[];

  /**
   * Expected JSON Web Encryption Compression Algorithms.
   */
  readonly expectedCompressionAlgorithms?: CompressionAlgorithm[];

  /**
   * Detached Ciphertext.
   */
  readonly detachedCiphertext?: Buffer;
}
