import { Buffer } from 'buffer';

import { InvalidJsonWebEncryptionError } from '../../../../errors/invalid-jsonwebencryption.error';
import { InvalidJsonWebKeyError } from '../../../../errors/invalid-jsonwebkey.error';
import { JsonWebEncryptionHeader } from '../../../../jwe/jsonwebencryption-header';
import { OctetSequenceJsonWebKey } from '../../../jwk/oct/octet-sequence.jsonwebkey';
import { RsaJsonWebKey } from '../../../jwk/rsa/rsa.jsonwebkey';
import { DirJsonWebEncryptionKeyManagementBackend } from './dir-jsonwebencryption-key-management.backend';

describe('Dir JSON Web Encryption Key Management Backend', () => {
  const contentEncryptionKey = Buffer.from('AAECAwQFBgcICQoLDA0ODw', 'base64url');

  describe('dir', () => {
    const backend = new DirJsonWebEncryptionKeyManagementBackend();

    const encryptedKey = Buffer.alloc(0);
    const jsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'AAECAwQFBgcICQoLDA0ODw' });
    const header = new JsonWebEncryptionHeader({ alg: 'dir', enc: 'A128GCM' });

    const wrongAlgJsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'AAECAwQFBgcICQoLDA0ODw', alg: 'HS256' });

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

    const badSizeEncryptedKey = Buffer.from('AAECAwQFBgcICQoLDA0ODw', 'base64url');

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

      it('should throw when the length of the Content Encryption Key is not supported by the Encryption Algorithm.', async () => {
        await expect(backend.unwrap(badSizeEncryptedKey, jsonWebKey, header)).rejects.toThrowWithMessage(
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

      it('should generate a Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(jsonWebKey, header)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });
    });
  });
});
