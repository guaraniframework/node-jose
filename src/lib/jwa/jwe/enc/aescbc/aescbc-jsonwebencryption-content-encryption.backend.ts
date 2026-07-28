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
   * @param cek Content Encryption Key.
   * @param aad Additional Authenticated Data.
   * @param iv Initialization Vector.
   * @throws {InvalidJsonWebEncryptionError} Failed to encrypt the provided Plaintext.
   * @returns Ciphertext and Authentication Tag.
   */
  public async encrypt(plaintext: Buffer, cek: Buffer, aad: Buffer, iv: Buffer): Promise<[Buffer, Buffer]> {
    this.validateContentEncryptionKey(cek);
    this.validateInitializationVector(iv);

    const macKey = cek.subarray(0, this.keySize);
    const encKey = cek.subarray(this.keySize);

    const cipher = createCipheriv(this.cipher, encKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

    const tag = this.getAuthTag(ciphertext, macKey, aad, iv);

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

    const macKey = cek.subarray(0, this.keySize);
    const encKey = cek.subarray(this.keySize);

    const expectedTag = this.getAuthTag(ciphertext, macKey, aad, iv);

    if (tag.length !== expectedTag.length || !timingSafeEqual(tag, expectedTag)) {
      throw new InvalidJsonWebEncryptionError('The provided JSON Web Encryption is invalid.');
    }

    const decipher = createDecipheriv(this.cipher, encKey, iv);

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  /**
   * Generates the Authentication Tag of the provided Ciphertext.
   *
   * @param ciphertext Ciphertext to be decrypted.
   * @param cek Content Encryption Key.
   * @param aad Additional Authenticated Data.
   * @param iv Initialization Vector.
   * @returns Authentication Tag.
   */
  private getAuthTag(ciphertext: Buffer, cek: Buffer, aad: Buffer, iv: Buffer): Buffer {
    const length = aad.length << 3;
    const buffer = Buffer.alloc(8);

    buffer.writeUInt32BE(Math.floor(length / 2 ** 32), 0);
    buffer.writeUInt32BE(length % 2 ** 32, 4);

    const data = Buffer.concat([aad, iv, ciphertext, buffer]);

    return createHmac(this.hash, cek).update(data).digest().subarray(0, this.keySize);
  }
}
