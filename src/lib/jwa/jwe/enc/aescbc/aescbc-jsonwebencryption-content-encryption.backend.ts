import { Buffer } from 'buffer';
import { createCipheriv, createDecipheriv, createHmac, timingSafeEqual } from 'crypto';

import { InvalidJsonWebEncryptionError } from '../../../../errors/invalid-jsonwebencryption.error';
import { ContentEncryptionAlgorithm } from '../content-encryption-algorithm.type';
import { JsonWebEncryptionContentEncryptionBackend } from '../jsonwebencryption-content-encryption.backend';

/**
 * Implementation of the AES CBC JSON Web Encryption Content Encryption Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2|RFC 7518 AES_CBC_HMAC_SHA2 Algorithms}
 */
export class AESCBCJsonWebEncryptionContentEncryptionBackend extends JsonWebEncryptionContentEncryptionBackend {
  /**
   * AES CBC JSON Web Encryption Content Encryption Algorithm.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2|RFC 7518 AES_CBC_HMAC_SHA2 Algorithms}
   */
  declare protected readonly algorithm: Extract<
    ContentEncryptionAlgorithm,
    'A128CBC-HS256' | 'A192CBC-HS384' | 'A256CBC-HS512'
  >;

  /**
   * Size of the Encryption Key and the MAC Key in bytes.
   */
  private readonly keySize: number;

  /**
   * Hash Algorithm.
   */
  private readonly hash: string;

  /**
   * Cipher Algorithm.
   */
  private readonly cipher: string;

  /**
   * Instantiates a new AES CBC JSON Web Encryption Content Encryption Backend.
   *
   * @param algorithm JSON Web Encryption Content Encryption Algorithm.
   */
  public constructor(
    algorithm: Extract<ContentEncryptionAlgorithm, 'A128CBC-HS256' | 'A192CBC-HS384' | 'A256CBC-HS512'>,
  ) {
    const [keySize, hashSize] = /^A([0-9]{3})CBC-HS([0-9]{3})$/
      .exec(algorithm)!
      .slice(1)
      .map((value) => Number.parseInt(value)) as [number, number];

    super(algorithm, keySize >> 2, 16);

    this.keySize = keySize >> 3;
    this.hash = `sha-${hashSize}`;
    this.cipher = `aes-${keySize}-cbc`;
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

    const macKey = contentEncryptionKey.subarray(0, this.keySize);
    const encKey = contentEncryptionKey.subarray(this.keySize);

    const cipher = createCipheriv(this.cipher, encKey, initializationVector);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

    const authenticationTag = this.getAuthTag(ciphertext, macKey, additionalAuthenticatedData, initializationVector);

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

    const macKey = contentEncryptionKey.subarray(0, this.keySize);
    const encKey = contentEncryptionKey.subarray(this.keySize);

    const expectedTag = this.getAuthTag(ciphertext, macKey, additionalAuthenticatedData, initializationVector);

    if (authenticationTag.length !== expectedTag.length || !timingSafeEqual(authenticationTag, expectedTag)) {
      throw new InvalidJsonWebEncryptionError('The provided JSON Web Encryption is invalid.');
    }

    const decipher = createDecipheriv(this.cipher, encKey, initializationVector);

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  /**
   * Generates the Authentication Tag of the provided Ciphertext.
   *
   * @param ciphertext Ciphertext to be decrypted.
   * @param contentEncryptionKey Content Encryption Key.
   * @param additionalAuthenticatedData Additional Authenticated Data.
   * @param initializationVector Initialization Vector.
   * @returns Authentication Tag.
   */
  private getAuthTag(
    ciphertext: Buffer,
    contentEncryptionKey: Buffer,
    additionalAuthenticatedData: Buffer,
    initializationVector: Buffer,
  ): Buffer {
    const length = additionalAuthenticatedData.length << 3;
    const buffer = Buffer.alloc(8);

    buffer.writeUInt32BE(Math.floor(length / 2 ** 32), 0);
    buffer.writeUInt32BE(length % 2 ** 32, 4);

    const data = Buffer.concat([additionalAuthenticatedData, initializationVector, ciphertext, buffer]);

    return createHmac(this.hash, contentEncryptionKey).update(data).digest().subarray(0, this.keySize);
  }
}
