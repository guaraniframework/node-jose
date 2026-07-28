import { Buffer } from 'buffer';
import crypto from 'crypto';

import { InvalidJsonWebEncryptionError } from '../../../../errors/invalid-jsonwebencryption.error';
import { AESCBCJsonWebEncryptionContentEncryptionBackend } from './aescbc-jsonwebencryption-content-encryption.backend';

jest.mock<typeof crypto>('crypto', () => ({
  ...jest.requireActual('crypto'),
  randomBytes: jest.fn().mockImplementation((size, cb) => cb(null, Buffer.alloc(size, 0x00))),
}));

describe('AES CBC JSON Web Encryption Content Encryption Backend', () => {
  const plaintext = Buffer.from('Super secret message.', 'utf8');
  const aad = Buffer.alloc(0);
  const iv = Buffer.from('AAAAAAAAAAAAAAAAAAAAAA', 'base64url');

  const badLengthIv = Buffer.from('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'base64url');

  const badCiphertext = Buffer.from('id4pfaiMSfjGeChypGzl5jV4_RtyN5qShHO9Djyaz2k', 'base64url');
  const badIv = Buffer.from('8ugOjchaHMDwOcPII2BWhw', 'base64url');
  const badAad = Buffer.alloc(1);

  describe('A128CBC-HS256', () => {
    const backend = new AESCBCJsonWebEncryptionContentEncryptionBackend('A128CBC-HS256');

    const ciphertext = Buffer.from('4i7-_mXyLjinjA3Q9fx7shLG1sHyDC6SQ_9OVtZzU-M', 'base64url');
    const cek = Buffer.from('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8', 'base64url');
    const tag = Buffer.from('DAVUFw9ZARV1ux5Y3Vi6CA', 'base64url');

    const badLengthCek = Buffer.from('1E8iEkKORbJq3o4Iq3JuxQ', 'base64url');

    const badCek = Buffer.from('6KZLfdkyIkYagFaaElP9xhZE7jO6wvuD_XTwx6oASVk', 'base64url');
    const badTag = Buffer.from('XBNd9px4iqzpAu_mKBzeng', 'base64url');

    describe('encrypt()', () => {
      it('should throw when the length of the provided Content Encryption Key is invalid.', async () => {
        await expect(backend.encrypt(plaintext, badLengthCek, aad, iv)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided Content Encryption Key is invalid.',
        );
      });

      it('should throw when the length of the provided Initialization Vector is invalid.', async () => {
        await expect(backend.encrypt(plaintext, cek, aad, badLengthIv)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided Initialization Vector is invalid.',
        );
      });

      it('should encrypt the provided Plaintext.', async () => {
        await expect(backend.encrypt(plaintext, cek, aad, iv)).resolves.toStrictEqual([ciphertext, tag]);
      });
    });

    describe('decrypt()', () => {
      it('should throw when the length of the provided Content Encryption Key is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, badLengthCek, aad, iv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided Content Encryption Key is invalid.',
        );
      });

      it('should throw when the length of the provided Initialization Vector is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, cek, aad, badLengthIv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided Initialization Vector is invalid.',
        );
      });

      it('should throw when the provided Ciphertext is invalid.', async () => {
        await expect(backend.decrypt(badCiphertext, cek, aad, iv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided Content Encryption Key is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, badCek, aad, iv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided Additional Authenticated Data is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, cek, badAad, iv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided Initialization Vector is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, cek, aad, badIv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided Authentication Tag is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, cek, aad, iv, badTag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should decrypt the provided Ciphertext.', async () => {
        await expect(backend.decrypt(ciphertext, cek, aad, iv, tag)).resolves.toStrictEqual(plaintext);
      });
    });

    describe('generateInitializationVector()', () => {
      it('should generate an Initialization Vector.', async () => {
        await expect(backend.generateInitializationVector()).resolves.toStrictEqual(iv);
      });
    });
  });

  describe('A192CBC-HS384', () => {
    const backend = new AESCBCJsonWebEncryptionContentEncryptionBackend('A192CBC-HS384');

    const ciphertext = Buffer.from('Rzc-nCIBUZsK8HAjAB4KA60VXWjmnCemM30Poujlt7o', 'base64url');
    const cek = Buffer.from('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v', 'base64url');
    const tag = Buffer.from('ckxgS8jLleWk4U7_s2z8-JdJdzcOV4ON', 'base64url');

    const badLengthCek = Buffer.from('86Mpm3txpeKWQqIMSilkUeNo8sdvmXKB', 'base64url');

    const badCek = Buffer.from('PfBSi7vja_wLS85-hUSg7sBWRyCLdN6QcIzRPnbatw4oaDdhW16goQrYvfWFlNV4', 'base64url');
    const badTag = Buffer.from('dpOCso84OhUib5vEJygn6jRKRVeexcA4', 'base64url');

    describe('encrypt()', () => {
      it('should throw when the length of the provided Content Encryption Key is invalid.', async () => {
        await expect(backend.encrypt(plaintext, badLengthCek, aad, iv)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided Content Encryption Key is invalid.',
        );
      });

      it('should throw when the length of the provided Initialization Vector is invalid.', async () => {
        await expect(backend.encrypt(plaintext, cek, aad, badLengthIv)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided Initialization Vector is invalid.',
        );
      });

      it('should encrypt the provided Plaintext.', async () => {
        await expect(backend.encrypt(plaintext, cek, aad, iv)).resolves.toStrictEqual([ciphertext, tag]);
      });
    });

    describe('decrypt()', () => {
      it('should throw when the length of the provided Content Encryption Key is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, badLengthCek, aad, iv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided Content Encryption Key is invalid.',
        );
      });

      it('should throw when the length of the provided Initialization Vector is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, cek, aad, badLengthIv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided Initialization Vector is invalid.',
        );
      });

      it('should throw when the provided Ciphertext is invalid.', async () => {
        await expect(backend.decrypt(badCiphertext, cek, aad, iv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided Content Encryption Key is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, badCek, aad, iv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided Additional Authenticated Data is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, cek, badAad, iv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided Initialization Vector is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, cek, aad, badIv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided Authentication Tag is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, cek, aad, iv, badTag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should decrypt the provided Ciphertext.', async () => {
        await expect(backend.decrypt(ciphertext, cek, aad, iv, tag)).resolves.toStrictEqual(plaintext);
      });
    });

    describe('generateInitializationVector()', () => {
      it('should generate an Initialization Vector.', async () => {
        await expect(backend.generateInitializationVector()).resolves.toStrictEqual(iv);
      });
    });
  });

  describe('A256CBC-HS512', () => {
    const backend = new AESCBCJsonWebEncryptionContentEncryptionBackend('A256CBC-HS512');

    const ciphertext = Buffer.from('beF1okLtAlp5RJDN84sAb7ubLkBxreRJzYQ5HHpQlbY', 'base64url');
    const cek = Buffer.from(
      'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw',
      'base64url',
    );
    const tag = Buffer.from('QKqpbDyl9dMstNhWZpqARnJRSKTvTZfvSfADUYAIDQo', 'base64url');

    const badLengthCek = Buffer.from('wLARG5KC1qensboTOzTtzUBOlyBcofxtPjBhrwIAwgc', 'base64url');

    const badCek = Buffer.from(
      '3W4hyOL4jOd-oprrMP6ekbjAafnWP86PLumqNFYmPUkMoWg7Tvimoy2gW-7sjOL7AjBllfjoboMCIDtmLVxZ9w',
      'base64url',
    );
    const badTag = Buffer.from('2HyIWq7GmrUSM4NuE1UkWfW-2xZ424a7NNib8TZdKxQ', 'base64url');

    describe('encrypt()', () => {
      it('should throw when the length of the provided Content Encryption Key is invalid.', async () => {
        await expect(backend.encrypt(plaintext, badLengthCek, aad, iv)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided Content Encryption Key is invalid.',
        );
      });

      it('should throw when the length of the provided Initialization Vector is invalid.', async () => {
        await expect(backend.encrypt(plaintext, cek, aad, badLengthIv)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided Initialization Vector is invalid.',
        );
      });

      it('should encrypt the provided Plaintext.', async () => {
        await expect(backend.encrypt(plaintext, cek, aad, iv)).resolves.toStrictEqual([ciphertext, tag]);
      });
    });

    describe('decrypt()', () => {
      it('should throw when the length of the provided Content Encryption Key is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, badLengthCek, aad, iv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided Content Encryption Key is invalid.',
        );
      });

      it('should throw when the length of the provided Initialization Vector is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, cek, aad, badLengthIv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided Initialization Vector is invalid.',
        );
      });

      it('should throw when the provided Ciphertext is invalid.', async () => {
        await expect(backend.decrypt(badCiphertext, cek, aad, iv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided Content Encryption Key is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, badCek, aad, iv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided Additional Authenticated Data is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, cek, badAad, iv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided Initialization Vector is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, cek, aad, badIv, tag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided Authentication Tag is invalid.', async () => {
        await expect(backend.decrypt(ciphertext, cek, aad, iv, badTag)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should decrypt the provided Ciphertext.', async () => {
        await expect(backend.decrypt(ciphertext, cek, aad, iv, tag)).resolves.toStrictEqual(plaintext);
      });
    });

    describe('generateInitializationVector()', () => {
      it('should generate an Initialization Vector.', async () => {
        await expect(backend.generateInitializationVector()).resolves.toStrictEqual(iv);
      });
    });
  });
});
