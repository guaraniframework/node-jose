import { Buffer } from 'buffer';
import { randomBytes } from 'crypto';
import { promisify } from 'util';

import { InvalidJsonWebEncryptionError } from '../../../errors/invalid-jsonwebencryption.error';
import { ContentEncryptionAlgorithm } from './content-encryption-algorithm.type';

const randomBytesAsync = promisify(randomBytes);

/**
 * Implementation of the JSON Web Encryption Content Encryption Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-5|RFC 7518 Cryptographic Algorithms for Content Encryption}
 */
export abstract class JsonWebEncryptionContentEncryptionBackend {
  /**
   * Size of the Content Encryption Key in bytes.
   */
  public readonly contentEncryptionKeySize: number;

  /**
   * Size of the Initialization Vector in bytes.
   */
  public readonly initializationVectorSize: number;

  /**
   * JSON Web Encryption Content Encryption Algorithm.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.2|RFC 7516 "enc" (Encryption Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1|RFC 7518 "enc" (Encryption Algorithm) Header Parameter Values for JWE}
   */
  protected readonly algorithm: ContentEncryptionAlgorithm;

  /**
   * Instantiates a new JSON Web Encryption Content Encryption Backend.
   *
   * @param algorithm JSON Web Encryption Content Encryption Algorithm.
   * @param contentEncryptionKeySize Size of the Content Encryption Key in bytes.
   * @param initializationVectorSize Size of the Initialization Vector in bytes.
   */
  public constructor(
    algorithm: ContentEncryptionAlgorithm,
    contentEncryptionKeySize: number,
    initializationVectorSize: number,
  ) {
    this.algorithm = algorithm;
    this.contentEncryptionKeySize = contentEncryptionKeySize;
    this.initializationVectorSize = initializationVectorSize;
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
  public abstract encrypt(
    plaintext: Buffer,
    contentEncryptionKey: Buffer,
    additionalAuthenticatedData: Buffer,
    initializationVector: Buffer,
  ): Promise<[Buffer, Buffer]>;

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
  public abstract decrypt(
    ciphertext: Buffer,
    contentEncryptionKey: Buffer,
    additionalAuthenticatedData: Buffer,
    initializationVector: Buffer,
    authenticationTag: Buffer,
  ): Promise<Buffer>;

  /**
   * Generates a new Initialization Vector.
   *
   * @returns Generated Initialization Vector.
   */
  public async generateInitializationVector(): Promise<Buffer> {
    return await randomBytesAsync(this.initializationVectorSize);
  }

  /**
   * Checks if the provided Content Encryption Key can be used.
   *
   * @param contentEncryptionKey Content Encryption Key to be checked.
   * @throws {InvalidJsonWebEncryptionError} The provided Content Encryption Key is invalid.
   */
  protected validateContentEncryptionKey(contentEncryptionKey: Buffer): void {
    if (contentEncryptionKey.length !== this.contentEncryptionKeySize) {
      throw new InvalidJsonWebEncryptionError('The provided Content Encryption Key is invalid.');
    }
  }

  /**
   * Checks if the provided Initialization Vector can be used.
   *
   * @param initializationVector Initialization Vector to be checked.
   * @throws {InvalidJsonWebEncryptionError} The provided Initialization Vector is invalid.
   */
  protected validateInitializationVector(initializationVector: Buffer): void {
    if (initializationVector.length !== this.initializationVectorSize) {
      throw new InvalidJsonWebEncryptionError('The provided Initialization Vector is invalid.');
    }
  }
}
