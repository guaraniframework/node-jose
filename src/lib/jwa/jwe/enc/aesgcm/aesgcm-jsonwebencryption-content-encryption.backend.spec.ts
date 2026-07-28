import { Buffer } from 'buffer';
import crypto from 'crypto';

import { InvalidJsonWebEncryptionError } from '../../../../errors/invalid-jsonwebencryption.error';
import { AESGCMJsonWebEncryptionContentEncryptionBackend } from './aesgcm-jsonwebencryption-content-encryption.backend';

jest.mock<typeof crypto>('crypto', () => ({
  ...jest.requireActual('crypto'),
  randomBytes: jest.fn().mockImplementation((size, cb) => cb(null, Buffer.alloc(size, 0x00))),
}));

describe('AES GCM JSON Web Encryption Content Encryption Backend', () => {
  const plaintext = Buffer.from('Super secret message.', 'utf8');
  const aad = Buffer.alloc(0);
  const iv = Buffer.from('AAAAAAAAAAAAAAAA', 'base64url');

  const badLengthIv = Buffer.from('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'base64url');

  const badCiphertext = Buffer.from('id4pfaiMSfjGeChypGzl5jV4_RtyN5qShHO9Djyaz2k', 'base64url');
  const badIv = Buffer.from('P_pzL8PROUrmbcu_', 'base64url');
  const badAad = Buffer.alloc(1);
  const badTag = Buffer.from('e96sbBdkxUh0OdsQTNK_NQ', 'base64url');

  describe('A128GCM', () => {
    const backend = new AESGCMJsonWebEncryptionContentEncryptionBackend('A128GCM');

    const ciphertext = Buffer.from('GqP3Nuu71emA-x8cQOzV7srMTEsa', 'base64url');
    const cek = Buffer.from('AAECAwQFBgcICQoLDA0ODw', 'base64url');
    const tag = Buffer.from('jGoLwZ2vNa8oghBPpwv5fw', 'base64url');

    const badLengthCek = Buffer.from('9F99GpSZ8NQ', 'base64url');

    const badCek = Buffer.from('Yca5ElyXe8nbWG7ozwqHIQ', 'base64url');

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

  describe('A192GCM', () => {
    const backend = new AESGCMJsonWebEncryptionContentEncryptionBackend('A192GCM');

    const ciphertext = Buffer.from('iHZi7sVtV0ngMCdS16dAtegT-cBf', 'base64url');
    const cek = Buffer.from('AAECAwQFBgcICQoLDA0ODxAREhMUFRYX', 'base64url');
    const tag = Buffer.from('aO3CNcjulrYcMKKdUiILOg', 'base64url');

    const badLengthCek = Buffer.from('oh96IXFBFnEdZbD9', 'base64url');

    const badCek = Buffer.from('JYsR5nY4nfNd4z5cc5R_U8jjvd-3I33z', 'base64url');

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

  describe('A256GCM', () => {
    const backend = new AESGCMJsonWebEncryptionContentEncryptionBackend('A256GCM');

    const ciphertext = Buffer.from('XcnFu8cM8Nhr2sxBOEH06qEiMTYG', 'base64url');
    const cek = Buffer.from('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8', 'base64url');
    const tag = Buffer.from('9ERsUHmKoxqutUPNmzOo3w', 'base64url');

    const badLengthCek = Buffer.from('uvd62vsiKoH5QQ4ILEy3cA', 'base64url');

    const badCek = Buffer.from('qTrWkARpKgbfcaxNrKGPFvdlNXnBm2PdASq_4506alY', 'base64url');

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
