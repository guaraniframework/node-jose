import { Buffer } from 'buffer';
import crypto from 'crypto';

import { InvalidJsonWebEncryptionError } from '../../../../errors/invalid-jsonwebencryption.error';
import { InvalidJsonWebKeyError } from '../../../../errors/invalid-jsonwebkey.error';
import { JsonWebEncryptionHeader } from '../../../../jwe/jsonwebencryption-header';
import { OctetSequenceJsonWebKey } from '../../../jwk/oct/octet-sequence.jsonwebkey';
import { RsaJsonWebKey } from '../../../jwk/rsa/rsa.jsonwebkey';
import { AESKWJsonWebEncryptionKeyManagementBackend } from './aeskw-jsonwebencryption-key-management.backend';

jest.mock<typeof crypto>('crypto', () => ({
  ...jest.requireActual('crypto'),
  randomBytes: jest.fn().mockImplementation((size, cb) => cb(null, Buffer.from([...Array(size).keys()]))),
}));

describe('AES Key Wrap JSON Web Encryption Key Management Backend', () => {
  const contentEncryptionKey = Buffer.from('AAECAwQFBgcICQoLDA0ODw', 'base64url');

  const wrongKtyJsonWebKey = new RsaJsonWebKey({
    kty: 'RSA',
    n:
      'xjpFydzTbByzL5jhEa2yQO63dpS9d9SKaN107AR69skKiTR4uK1c4SzDt4YcurDB' +
      'yhgKNzeBo6Vq3IRrkrltp97LKWfeZdM-leGt8-UTZEWqrNf3UGOEj8kI6lbjiG-S' +
      'n_yNHcVA9qBV22norZkgXctHLeFbY6TmpD-I8_UiplZUHoc9KlYc7crCQRa-O7tK' +
      'FDULNTMjjifc0dmuYP7ZcYAZXmRmoOpQuDr8s7OZY7TAqN0btMfA7RpUCWLT6TMR' +
      'QPX8GcyTxfbkOrSTFueKMHVNdXDtl068XXJ9mkjORiEmwlzqSBoxdeLWcNf_u20S' +
      '5JG5iK0nsm1uZYu-02XN-w',
    e: 'AQAB',
  });

  describe('A128KW', () => {
    const backend = new AESKWJsonWebEncryptionKeyManagementBackend('A128KW');

    const encryptedKey = Buffer.from('k1o-sQHDSt0CXhcLRv8Nsj5cL66Mj4Nw', 'base64url');
    const jsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'AAECAwQFBgcICQoLDA0ODw' });
    const header = new JsonWebEncryptionHeader({ alg: 'A128KW', enc: 'A128GCM' });

    const wrongAlgJsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'AAECAwQFBgcICQoLDA0ODw', alg: 'HS256' });

    const badSizeJsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYX' });

    const wrongEncryptedKey = Buffer.from('VJBm6T4_p5MNZCsW4lu050IbEWJpedBF', 'base64url');
    const wrongJsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'bSc_THqy4KVV6mwfYr7t4Q' });

    describe('wrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.wrap(contentEncryptionKey, wrongAlgJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.wrap(contentEncryptionKey, <any>wrongKtyJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.wrap(contentEncryptionKey, badSizeJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 16 bytes.',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, header)).resolves.toStrictEqual(encryptedKey);
      });
    });

    describe('unwrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.unwrap(encryptedKey, wrongAlgJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.unwrap(encryptedKey, <any>wrongKtyJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.unwrap(encryptedKey, badSizeJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 16 bytes.',
        );
      });

      it('should throw when the provided Encrypted Key is invalid.', async () => {
        await expect(backend.unwrap(wrongEncryptedKey, jsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided JSON Web Key is invalid.', async () => {
        await expect(backend.unwrap(encryptedKey, wrongJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should unwrap the provided Encrypted Key.', async () => {
        await expect(backend.unwrap(encryptedKey, jsonWebKey, header)).resolves.toStrictEqual(contentEncryptionKey);
      });
    });

    describe('generateContentEncryptionKey()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.generateContentEncryptionKey(wrongAlgJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.generateContentEncryptionKey(<any>wrongKtyJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.generateContentEncryptionKey(badSizeJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 16 bytes.',
        );
      });

      it('should generate a Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(jsonWebKey, header)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });
  });

  describe('A192KW', () => {
    const backend = new AESKWJsonWebEncryptionKeyManagementBackend('A192KW');

    const encryptedKey = Buffer.from('VJBm6T4_p5MNZCsW4lu050IbEWJpedBF', 'base64url');
    const jsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYX' });
    const header = new JsonWebEncryptionHeader({ alg: 'A192KW', enc: 'A128GCM' });

    const wrongAlgJsonWebKey = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYX',
      alg: 'HS256',
    });

    const badSizeJsonWebKey = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
    });

    const wrongEncryptedKey = Buffer.from('jMS_7Kip8vOMiyg5Lx6PSz5aX9LyC9aI', 'base64url');
    const wrongJsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'n16iBJM9W-JXIPjlLsoTfTcivlWrlIaW' });

    describe('wrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.wrap(contentEncryptionKey, wrongAlgJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.wrap(contentEncryptionKey, <any>wrongKtyJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.wrap(contentEncryptionKey, badSizeJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 24 bytes.',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, header)).resolves.toStrictEqual(encryptedKey);
      });
    });

    describe('unwrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.unwrap(encryptedKey, wrongAlgJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.unwrap(encryptedKey, <any>wrongKtyJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.unwrap(encryptedKey, badSizeJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 24 bytes.',
        );
      });

      it('should throw when the provided Encrypted Key is invalid.', async () => {
        await expect(backend.unwrap(wrongEncryptedKey, jsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided JSON Web Key is invalid.', async () => {
        await expect(backend.unwrap(encryptedKey, wrongJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should unwrap the provided Encrypted Key.', async () => {
        await expect(backend.unwrap(encryptedKey, jsonWebKey, header)).resolves.toStrictEqual(contentEncryptionKey);
      });
    });

    describe('generateContentEncryptionKey()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.generateContentEncryptionKey(wrongAlgJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.generateContentEncryptionKey(<any>wrongKtyJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.generateContentEncryptionKey(badSizeJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 24 bytes.',
        );
      });

      it('should generate a Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(jsonWebKey, header)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });
  });

  describe('A256KW', () => {
    const backend = new AESKWJsonWebEncryptionKeyManagementBackend('A256KW');

    const encryptedKey = Buffer.from('jMS_7Kip8vOMiyg5Lx6PSz5aX9LyC9aI', 'base64url');
    const jsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8' });
    const header = new JsonWebEncryptionHeader({ alg: 'A256KW', enc: 'A128GCM' });

    const wrongAlgJsonWebKey = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
      alg: 'HS256',
    });

    const badSizeJsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'AAECAwQFBgcICQoLDA0ODw' });

    const wrongEncryptedKey = Buffer.from('k1o-sQHDSt0CXhcLRv8Nsj5cL66Mj4Nw', 'base64url');

    const wrongJsonWebKey = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: 'ZlDHyJ4NcRBxFBbC_JL6csK-SXBWYZkDaIz_GoZy7Tw',
    });

    describe('wrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.wrap(contentEncryptionKey, wrongAlgJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.wrap(contentEncryptionKey, <any>wrongKtyJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.wrap(contentEncryptionKey, badSizeJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 32 bytes.',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        await expect(backend.wrap(contentEncryptionKey, jsonWebKey, header)).resolves.toStrictEqual(encryptedKey);
      });
    });

    describe('unwrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.unwrap(encryptedKey, wrongAlgJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.unwrap(encryptedKey, <any>wrongKtyJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.unwrap(encryptedKey, badSizeJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 32 bytes.',
        );
      });

      it('should throw when the provided Encrypted Key is invalid.', async () => {
        await expect(backend.unwrap(wrongEncryptedKey, jsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided JSON Web Key is invalid.', async () => {
        await expect(backend.unwrap(encryptedKey, wrongJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should unwrap the provided Encrypted Key.', async () => {
        await expect(backend.unwrap(encryptedKey, jsonWebKey, header)).resolves.toStrictEqual(contentEncryptionKey);
      });
    });

    describe('generateContentEncryptionKey()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.generateContentEncryptionKey(wrongAlgJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.generateContentEncryptionKey(<any>wrongKtyJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.generateContentEncryptionKey(badSizeJsonWebKey, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 32 bytes.',
        );
      });

      it('should generate a Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(jsonWebKey, header)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });
  });
});
