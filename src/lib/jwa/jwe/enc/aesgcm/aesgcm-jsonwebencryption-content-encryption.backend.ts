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
   * @param cek Content Encryption Key.
   * @param aad Additional Authenticated Data.
   * @param iv Initialization Vector.
   * @throws {InvalidJsonWebEncryptionError} Failed to encrypt the provided Plaintext.
   * @returns Ciphertext and Authentication Tag.
   */
  public async encrypt(plaintext: Buffer, cek: Buffer, aad: Buffer, iv: Buffer): Promise<[Buffer, Buffer]> {
    this.validateContentEncryptionKey(cek);
    this.validateInitializationVector(iv);

    const cipher = createCipheriv(this.cipher, cek, iv, { authTagLength: 16 });
    cipher.setAAD(aad);

    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    return [ciphertext, tag];
  }

  /**
   * Decrypts the provided Ciphertext.
   *
   * @param ciphertext Ciphertext to be decrypted.
   * @param cek Content Encryption Key.
   * @param aad Additional Authenticated Data.
   * @param iv Initialization Vector.
   * @param tag Authentication Tag.
   * @throws {InvalidJsonWebEncryptionError} Failed to decrypt the provided Ciphertext.
   * @returns Plaintext.
   */
  public async decrypt(ciphertext: Buffer, cek: Buffer, aad: Buffer, iv: Buffer, tag: Buffer): Promise<Buffer> {
    this.validateContentEncryptionKey(cek);
    this.validateInitializationVector(iv);

    const decipher = createDecipheriv(this.cipher, cek, iv, { authTagLength: 16 });

    decipher.setAAD(aad);
    decipher.setAuthTag(tag);

    try {
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch (error: unknown) {
      throw new InvalidJsonWebEncryptionError('The provided JSON Web Encryption is invalid.', { cause: error });
    }
  }
}
