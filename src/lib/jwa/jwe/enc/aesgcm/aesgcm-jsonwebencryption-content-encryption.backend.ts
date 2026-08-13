import { Buffer } from 'buffer';
import { CipherGCMTypes, createCipheriv, createDecipheriv } from 'crypto';

import { InvalidJsonWebEncryptionError } from '../../../../errors/invalid-jsonwebencryption.error';
import { ContentEncryptionAlgorithm } from '../content-encryption-algorithm.type';
import { JsonWebEncryptionContentEncryptionBackend } from '../jsonwebencryption-content-encryption.backend';

/**
 * Implementation of the AES GCM JSON Web Encryption Content Encryption Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-5.3|RFC 7518 Content Encryption with AES GCM}
 */
export class AESGCMJsonWebEncryptionContentEncryptionBackend extends JsonWebEncryptionContentEncryptionBackend {
  /**
   * AES GCM JSON Web Encryption Content Encryption Algorithm.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-5.3|RFC 7518 Content Encryption with AES GCM}
   */
  declare protected readonly algorithm: Extract<ContentEncryptionAlgorithm, 'A128GCM' | 'A192GCM' | 'A256GCM'>;

  /**
   * Cipher Algorithm.
   */
  private readonly cipher: CipherGCMTypes;

  /**
   * Instantiates a new AES GCM JSON Web Encryption Encryption Backend.
   *
   * @param algorithm JSON Web Encryption Encryption Algorithm.
   */
  public constructor(algorithm: Extract<ContentEncryptionAlgorithm, 'A128GCM' | 'A192GCM' | 'A256GCM'>) {
    const cekSize = Number.parseInt(algorithm.substring(1, 4));

    super(algorithm, cekSize >> 3, 12);

    this.cipher = `aes-${cekSize}-gcm` as CipherGCMTypes;
  }

  /**
   * Encrypts the provided Plaintext and Additional Authenticated Data.
   *
   * @param plaintext Plaintext to be encrypted.
   * @param contentEncryptionKey Content Encryption Key.
   * @param additionalAuthenticatedData Additional Authenticated Data.
   * @param initializationVector Initialization Vector.
   * @throws {InvalidJsonWebEncryptionError} Failed to encrypt the provided Plaintext.
   * @returns Ciphertext and Authentication Tag.
   */
  public async encrypt(
    plaintext: Buffer,
    contentEncryptionKey: Buffer,
    additionalAuthenticatedData: Buffer,
    initializationVector: Buffer,
  ): Promise<[Buffer, Buffer]> {
    this.validateContentEncryptionKey(contentEncryptionKey);
    this.validateInitializationVector(initializationVector);

    const cipher = createCipheriv(this.cipher, contentEncryptionKey, initializationVector, { authTagLength: 16 });
    cipher.setAAD(additionalAuthenticatedData);

    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authenticationTag = cipher.getAuthTag();

    return [ciphertext, authenticationTag];
  }

  /**
   * Decrypts the provided Ciphertext.
   *
   * @param ciphertext Ciphertext to be decrypted.
   * @param contentEncryptionKey Content Encryption Key.
   * @param additionalAuthenticatedData Additional Authenticated Data.
   * @param initializationVector Initialization Vector.
   * @param authenticationTag Authentication Tag.
   * @throws {InvalidJsonWebEncryptionError} Failed to decrypt the provided Ciphertext.
   * @returns Plaintext.
   */
  public async decrypt(
    ciphertext: Buffer,
    contentEncryptionKey: Buffer,
    additionalAuthenticatedData: Buffer,
    initializationVector: Buffer,
    authenticationTag: Buffer,
  ): Promise<Buffer> {
    this.validateContentEncryptionKey(contentEncryptionKey);
    this.validateInitializationVector(initializationVector);

    const decipher = createDecipheriv(this.cipher, contentEncryptionKey, initializationVector, { authTagLength: 16 });

    decipher.setAAD(additionalAuthenticatedData);
    decipher.setAuthTag(authenticationTag);

    try {
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch (error: unknown) {
      throw new InvalidJsonWebEncryptionError('The provided JSON Web Encryption is invalid.', { cause: error });
    }
  }
}
