import { isNonEmptyString } from '@guarani/primitives';

import { InvalidJoseHeaderError } from '../errors/invalid-jose-header.error';
import { JoseHeader } from '../jose/jose-header';
import { AESGCMKWJsonWebEncryptionKeyManagementBackend } from '../jwa/jwe/alg/aesgcmkw/aesgcmkw-jsonwebencryption-key-management.backend';
import { AESKWJsonWebEncryptionKeyManagementBackend } from '../jwa/jwe/alg/aeskw/aeskw-jsonwebencryption-key-management.backend';
import { DirJsonWebEncryptionKeyManagementBackend } from '../jwa/jwe/alg/dir/dir-jsonwebencryption-key-management.backend';
import { ECDHESJsonWebEncryptionKeyManagementBackend } from '../jwa/jwe/alg/ecdhes/ecdhes-jsonwebencryption-key-management.backend';
import { JsonWebEncryptionKeyManagementBackend } from '../jwa/jwe/alg/jsonwebencryption-key-management.backend';
import { KeyManagementAlgorithm } from '../jwa/jwe/alg/key-management-algorithm.type';
import { PBES2JsonWebEncryptionKeyManagementBackend } from '../jwa/jwe/alg/pbes2/pbes2-jsonwebencryption-key-management.backend';
import { RSAESJsonWebEncryptionKeyManagementBackend } from '../jwa/jwe/alg/rsaes/rsaes-jsonwebencryption-key-management.backend';
import { AESCBCJsonWebEncryptionContentEncryptionBackend } from '../jwa/jwe/enc/aescbc/aescbc-jsonwebencryption-content-encryption.backend';
import { AESGCMJsonWebEncryptionContentEncryptionBackend } from '../jwa/jwe/enc/aesgcm/aesgcm-jsonwebencryption-content-encryption.backend';
import { ContentEncryptionAlgorithm } from '../jwa/jwe/enc/content-encryption-algorithm.type';
import { JsonWebEncryptionContentEncryptionBackend } from '../jwa/jwe/enc/jsonwebencryption-content-encryption.backend';
import { CompressionAlgorithm } from '../jwa/jwe/zip/compression-algorithm.type';
import { DEFJsonWebEncryptionCompressionBackend } from '../jwa/jwe/zip/def/def-jsonwebencryption-compression.backend';
import { JsonWebEncryptionCompressionBackend } from '../jwa/jwe/zip/jsonwebencryption-compression.backend';
import { JsonWebEncryptionHeaderParameters } from './jsonwebencryption-header.parameters';

/**
 * Implementation of the JSON Web Encryption Header.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4|RFC 7516 JOSE Header}
 */
export class JsonWebEncryptionHeader<
  T extends JsonWebEncryptionHeaderParameters = JsonWebEncryptionHeaderParameters,
> extends JoseHeader {
  /**
   * Supported JSON Web Encryption Key Management Algorithms.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1|RFC 7516 "alg" (Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWE}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2|RFC 8037 ECDH-ES}
   */
  public static readonly keyManagementAlgorithms: KeyManagementAlgorithm[] = [
    'A128GCMKW',
    'A128KW',
    'A192GCMKW',
    'A192KW',
    'A256GCMKW',
    'A256KW',
    'ECDH-ES',
    'ECDH-ES+A128KW',
    'ECDH-ES+A192KW',
    'ECDH-ES+A256KW',
    'PBES2-HS256+A128KW',
    'PBES2-HS384+A192KW',
    'PBES2-HS512+A256KW',
    'RSA-OAEP',
    'RSA-OAEP-256',
    'RSA-OAEP-384',
    'RSA-OAEP-512',
    'RSA1_5',
    'dir',
  ];

  /**
   * Supported JSON Web Encryption Content Encryption Algorithms.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.2|RFC 7516 "enc" (Encryption Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1|RFC 7518 "enc" (Encryption Algorithm) Header Parameter Values for JWE}
   */
  public static readonly contentEncryptionAlgorithms: ContentEncryptionAlgorithm[] = [
    'A128CBC-HS256',
    'A128GCM',
    'A192CBC-HS384',
    'A192GCM',
    'A256CBC-HS512',
    'A256GCM',
  ];

  /**
   * Supported JSON Web Encryption Compression Algorithms.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3|RFC 7516 "zip" (Compression Algorithm) Header Parameter}
   */
  public static readonly compressionAlgorithms: CompressionAlgorithm[] = ['DEF'];

  /**
   * JSON Web Encryption Header Parameters.
   */
  declare public readonly parameters: T;

  /**
   * JSON Web Encryption Key Management Backend.
   */
  public readonly keyManagementBackend: JsonWebEncryptionKeyManagementBackend;

  /**
   * JSON Web Encryption Content Encryption Backend.
   */
  public readonly contentEncryptionBackend: JsonWebEncryptionContentEncryptionBackend;

  /**
   * JSON Web Encryption Compression Backend.
   */
  public readonly compressionBackend?: JsonWebEncryptionCompressionBackend;

  /**
   * Instantiates a new JSON Web Encryption Header.
   *
   * @param parameters JSON Web Encryption Header Parameters.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters are invalid.
   */
  public constructor(parameters: T) {
    super(parameters);

    this.keyManagementBackend = JsonWebEncryptionHeader.getKeyManagementBackend(parameters);
    this.contentEncryptionBackend = JsonWebEncryptionHeader.getContentEncryptionBackend(parameters);
    this.compressionBackend = JsonWebEncryptionHeader.getCompressionBackend(parameters)!;
  }

  /**
   * Validates the provided JOSE Header Parameters.
   *
   * @param parameters JOSE Header Parameters.
   * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters are invalid.
   */
  protected static override validateJoseHeaderParameters(parameters: JsonWebEncryptionHeaderParameters): void {
    super.validateJoseHeaderParameters(parameters);

    if (!isNonEmptyString(parameters.alg) || !this.keyManagementAlgorithms.includes(parameters.alg)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "alg".');
    }

    if (!isNonEmptyString(parameters.enc) || !this.contentEncryptionAlgorithms.includes(parameters.enc)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "enc".');
    }

    if (
      'zip' in parameters &&
      (!isNonEmptyString(parameters.zip) || !this.compressionAlgorithms.includes(parameters.zip))
    ) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "zip".');
    }
  }

  // #region Private Methods.
  private static getKeyManagementBackend(
    parameters: JsonWebEncryptionHeaderParameters,
  ): JsonWebEncryptionKeyManagementBackend {
    switch (parameters.alg) {
      case 'A128GCMKW':
      case 'A192GCMKW':
      case 'A256GCMKW':
        return new AESGCMKWJsonWebEncryptionKeyManagementBackend(parameters.alg);

      case 'A128KW':
      case 'A192KW':
      case 'A256KW':
        return new AESKWJsonWebEncryptionKeyManagementBackend(parameters.alg);

      case 'ECDH-ES':
      case 'ECDH-ES+A128KW':
      case 'ECDH-ES+A192KW':
      case 'ECDH-ES+A256KW':
        return new ECDHESJsonWebEncryptionKeyManagementBackend(parameters.alg);

      case 'PBES2-HS256+A128KW':
      case 'PBES2-HS384+A192KW':
      case 'PBES2-HS512+A256KW':
        return new PBES2JsonWebEncryptionKeyManagementBackend(parameters.alg);

      case 'RSA-OAEP':
      case 'RSA-OAEP-256':
      case 'RSA-OAEP-384':
      case 'RSA-OAEP-512':
      case 'RSA1_5':
        return new RSAESJsonWebEncryptionKeyManagementBackend(parameters.alg);

      case 'dir':
        return new DirJsonWebEncryptionKeyManagementBackend();
    }
  }

  private static getContentEncryptionBackend(
    parameters: JsonWebEncryptionHeaderParameters,
  ): JsonWebEncryptionContentEncryptionBackend {
    switch (parameters.enc) {
      case 'A128CBC-HS256':
      case 'A192CBC-HS384':
      case 'A256CBC-HS512':
        return new AESCBCJsonWebEncryptionContentEncryptionBackend(parameters.enc);

      case 'A128GCM':
      case 'A192GCM':
      case 'A256GCM':
        return new AESGCMJsonWebEncryptionContentEncryptionBackend(parameters.enc);
    }
  }

  private static getCompressionBackend(
    parameters: JsonWebEncryptionHeaderParameters,
  ): JsonWebEncryptionCompressionBackend | undefined {
    switch (parameters.zip) {
      case 'DEF':
        return new DEFJsonWebEncryptionCompressionBackend();

      default:
        return undefined;
    }
  }
  // #endregion
}
